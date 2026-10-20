"""XOR Primitive Finder for IDA Pro 9.3 (IDAPython).

Decodes instructions, finds XOR-family instructions and ranks functions by how
likely they are to contain XOR-based encoding. Zeroing forms (xor eax, eax;
eor x0, x1, x1; vpxor xmm0, xmm1, xmm1) are detected from decoded register
operands and excluded from the score.
Usage: File -> Script file...
"""

import collections

import ida_idp
import ida_kernwin
import ida_lines
import ida_ua
import idautils
import idc


# ---------------------------------------------------------------------------
#   Configuration
# ---------------------------------------------------------------------------

TITLE = "XOR Primitive Finder"
LOG_TAG = "[XOR Prims]"

# Prefixes of instruction names in the current processor module's table.
XOR_PREFIXES = ("xor", "pxor", "vpxor", "vxor", "eor", "veor")
SHIFT_ROTATE_PREFIXES = (
    "rol", "ror", "shl", "shr", "sar", "sal", "shld", "shrd",
    "lsl", "lsr", "asr", "rrx",
)
MIX_PREFIXES = SHIFT_ROTATE_PREFIXES + (
    "add", "sub", "adc", "sbb", "mul", "imul", "madd", "msub",
    "and", "or", "orr", "bic", "not", "mvn", "neg", "rsb", "bswap", "rev", "rbit",
)
# Exact names avoid broad "b*" matches such as BIC.
BRANCH_EXACT = {
    "b", "ba", "bal", "bc", "bcc", "bcs", "beq", "bne", "bgt", "bge", "blt",
    "ble", "bhi", "bls", "bvs", "bvc", "bmi", "bpl", "bhs", "blo", "br", "bra",
    "brw", "bl", "blx", "bx", "bxj", "jmp", "ljmp", "jmpq", "call", "callq",
}
BRANCH_PREFIXES = ("j", "loop", "cbz", "cbnz", "tbz", "tbnz")

MAX_OPERANDS = getattr(ida_ua, "UA_MAXOP", 8)

COLUMNS = [
    ["Function", 28],
    ["XORs", 6 | ida_kernwin.Choose.CHCOL_DEC],
    ["Useful", 7 | ida_kernwin.Choose.CHCOL_DEC],
    ["Zeroing", 8 | ida_kernwin.Choose.CHCOL_DEC],
    ["Loops", 6 | ida_kernwin.Choose.CHCOL_DEC],
    ["Score", 6 | ida_kernwin.Choose.CHCOL_DEC],
    ["Rating", 8],
    ["Sample", 40],
]

Itypes = collections.namedtuple("Itypes", "names xor mix rotate branch")
ITYPES = None        # filled by build_itypes()
_chooser = None      # keep a reference while the window is open


# ---------------------------------------------------------------------------
#   Helpers
# ---------------------------------------------------------------------------

def log(message):
    ida_kernwin.msg("%s %s\n" % (LOG_TAG, message))


def disasm(ea):
    line = idc.generate_disasm_line(ea, 0) or ""
    return ida_lines.tag_remove(line).strip()


def func_name(ea):
    return idc.get_func_name(ea) or ("sub_%X" % ea)


def build_itypes():
    """Map the active processor module's instruction table to itype sets.

    itype codes are processor-specific: entry i of ph_get_instruc() has the
    code ph_get_instruc_start() + i.
    """
    try:
        first = int(ida_idp.ph_get_instruc_start())
        last = int(ida_idp.ph_get_instruc_end())
        table = ida_idp.ph_get_instruc()
    except Exception as exc:
        raise RuntimeError("cannot read the processor instruction table: %s" % exc)
    if not table:
        raise RuntimeError("the processor instruction table is empty")

    count = min(len(table), (last - first) or len(table))
    names = {}
    for index in range(count):
        name = str(table[index][0] or "").lower().replace(" ", "")
        if name:
            names[first + index] = name
    if not names:
        raise RuntimeError("cannot map instruction types to names")

    def select(prefixes, exact=()):
        return {itype for itype, name in names.items()
                if name in exact or name.startswith(prefixes)}

    itypes = Itypes(
        names=names,
        xor=select(XOR_PREFIXES),
        mix=select(MIX_PREFIXES),
        rotate=select(SHIFT_ROTATE_PREFIXES),
        branch=select(BRANCH_PREFIXES, BRANCH_EXACT),
    )
    if not itypes.xor:
        raise RuntimeError("no XOR-like instructions in this processor's table")
    return itypes


def decode(ea):
    """Decode the instruction at ea without touching the database."""
    insn = ida_ua.insn_t()
    try:
        return insn if ida_ua.decode_insn(insn, ea) > 0 else None
    except Exception:
        return None


def explicit_operands(insn):
    ops = []
    for index in range(MAX_OPERANDS):
        op = insn.ops[index]
        if op.type == ida_ua.o_void:
            break
        ops.append(op)
    return ops


def register_of(op):
    return int(op.reg) if op.type == ida_ua.o_reg else None


def is_zeroing_xor(insn):
    """dst ^= src with dst == src, or dst = src1 ^ src2 with src1 == src2."""
    ops = explicit_operands(insn)
    if len(ops) == 2:
        regs = register_of(ops[0]), register_of(ops[1])
    elif len(ops) == 3:
        regs = register_of(ops[1]), register_of(ops[2])
    else:
        return False    # do not guess for unusual forms
    return regs[0] is not None and regs[0] == regs[1]


def is_backward_branch(ea, insn, func_start):
    """Direct branch to an earlier address of the same function (a loop edge)."""
    if int(insn.itype) not in ITYPES.branch:
        return False
    ops = explicit_operands(insn)
    if not ops or ops[0].type not in (ida_ua.o_near, ida_ua.o_far):
        return False
    return func_start <= int(ops[0].addr) < ea


# ---------------------------------------------------------------------------
#   Scoring
# ---------------------------------------------------------------------------

def score_function(useful, mix, rotate, back_edges, dst_registers, insn_count):
    if useful <= 0:
        return 0    # zeroing-only functions are never candidates

    score = 1 if useful == 1 else 2 if useful == 2 else 3 if useful <= 4 else 4 if useful <= 7 else 5
    score += (mix >= 4) * 2 + (mix >= 8)
    score += (back_edges >= 1) * 2 + (back_edges >= 3)
    score += rotate >= 2

    # The same destination reused by several XORs hints at an accumulator.
    counts = collections.Counter(dst_registers)
    score += bool(counts) and max(counts.values()) >= 2
    score += bool(insn_count) and useful >= 3 and useful / float(insn_count) >= 0.08
    return int(score)


def rating(score, useful):
    if useful >= 3 and score >= 7:
        return "High"
    return "Medium" if score >= 4 else "Low"


# ---------------------------------------------------------------------------
#   Scan
# ---------------------------------------------------------------------------

def analyze_function(func_ea):
    """Return a result row for a function containing XOR-like instructions."""
    useful, zeroing, all_xor, dst_registers, back_edges = [], [], [], [], []
    mix = rotate = insn_count = 0

    for ea in idautils.FuncItems(func_ea):
        insn = decode(ea)
        if insn is None:
            continue
        insn_count += 1
        itype = int(insn.itype)
        mix += itype in ITYPES.mix
        rotate += itype in ITYPES.rotate
        if is_backward_branch(ea, insn, func_ea):
            back_edges.append(ea)
        if itype not in ITYPES.xor:
            continue

        all_xor.append(ea)
        if is_zeroing_xor(insn):
            zeroing.append(ea)
        else:
            useful.append(ea)
            ops = explicit_operands(insn)
            dst = register_of(ops[0]) if ops else None
            if dst is not None:
                dst_registers.append(dst)

    if not all_xor:
        return None

    score = score_function(len(useful), mix, rotate, len(back_edges), dst_registers, insn_count)
    first_ea = useful[0] if useful else all_xor[0]
    return {
        "ea": first_ea,
        "name": func_name(func_ea),
        "xor": len(all_xor),
        "useful": len(useful),
        "zeroing": len(zeroing),
        "loops": len(back_edges),
        "score": score,
        "rating": rating(score, len(useful)),
    }


def scan():
    results = []
    total = 0
    ida_kernwin.clr_cancelled()
    ida_kernwin.show_wait_box("NODELAY\nDecoding functions...")
    try:
        for func_ea in idautils.Functions():
            total += 1
            if total % 256 == 0:
                if ida_kernwin.user_cancelled():
                    log("Scan cancelled, results are partial.")
                    break
                ida_kernwin.replace_wait_box("Decoding functions... %d" % total)
            try:
                item = analyze_function(func_ea)
            except Exception as exc:
                log("Failed to scan 0x%X: %s" % (func_ea, exc))
                continue
            if item:
                results.append(item)
    finally:
        ida_kernwin.hide_wait_box()

    results.sort(key=lambda r: (r["score"], r["useful"], r["xor"]), reverse=True)
    return results, total


# ---------------------------------------------------------------------------
#   Chooser
# ---------------------------------------------------------------------------

class ResultChooser(ida_kernwin.Choose):
    """Rows are (ea, [cells...]); the Address column is added automatically."""

    def __init__(self, title, columns, rows):
        cols = [["Address", 14 | ida_kernwin.Choose.CHCOL_EA]] + columns
        super().__init__(title, cols, flags=ida_kernwin.Choose.CH_QFLT)
        self.rows = rows

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        ea, cells = self.rows[n]
        return ["0x%X" % ea] + list(cells)

    def OnGetEA(self, n):
        return self.rows[n][0]


def show_results(results):
    """Address = first non-zeroing XOR (or the first XOR if all are zeroing)."""
    global _chooser
    if not results:
        log("No XOR-like instructions found.")
        return
    rows = [
        (r["ea"], [r["name"], str(r["xor"]), str(r["useful"]), str(r["zeroing"]),
                   str(r["loops"]), str(r["score"]), r["rating"], disasm(r["ea"])])
        for r in results
    ]
    _chooser = ResultChooser(TITLE, COLUMNS, rows)
    _chooser.Show()


# ---------------------------------------------------------------------------
#   Main
# ---------------------------------------------------------------------------

def main():
    global ITYPES
    try:
        ITYPES = build_itypes()
    except RuntimeError as exc:
        log("Initialisation failed: %s" % exc)
        return

    log("Instruction types: %d, XOR-like: %d" % (len(ITYPES.names), len(ITYPES.xor)))
    results, total = scan()
    log("Functions scanned: %d, with XOR: %d, XOR insns: %d (zeroing: %d)" % (
        total, len(results),
        sum(r["xor"] for r in results), sum(r["zeroing"] for r in results)))
    show_results(results)


if __name__ == "__main__":
    main()
