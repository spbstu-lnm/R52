"""XOR Primitive Finder for IDA Pro 9.3 (IDAPython).

    | Decodes instructions, detects instructions from XOR family,
    | and ranks functions by XOR-based encoding likelihood.

self-XOR zeroing forms are detected from decoded register operands and are
excluded from the heuristic score for XOR-based encoding. Examples:
    x86:      xor eax, eax
    AArch64:  eor x0, x1, x1
    AVX:      vpxor xmm0, xmm1, xmm1

USAGE: File -> Script file...

double-click a result row to jump to the first non-zeroing XOR (or the first
self-XOR if the function only contains zeroing XOR instructions).
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

WINDOW_TITLE = "XOR Primitive Finder"

# These are names in the *current processor module's instruction table*, not
# text parsed from disassembly output. They are converted to itype sets once.
XOR_TYPE_PREFIXES = (
    "xor", "pxor", "vpxor", "eor", "veor", "pdp_xor",
)

MIX_TYPE_PREFIXES = (
    "add", "sub", "adc", "sbb", "mul", "imul", "madd", "msub",
    "rol", "ror", "shl", "shr", "sar", "sal", "shld", "shrd",
    "lsl", "lsr", "asr", "rrx", "and", "or", "orr", "bic", "not",
    "mvn", "neg", "rsb", "bswap", "rev", "rbit",
)

SHIFT_ROTATE_TYPE_PREFIXES = (
    "rol", "ror", "shl", "shr", "sar", "sal", "shld", "shrd",
    "lsl", "lsr", "asr", "rrx",
)

# Branch types are also sourced from the processor's instruction table. The
# exact list catches common ISAs while avoiding broad "b*" matches such as BIC.
BRANCH_TYPE_EXACT = {
    "b", "ba", "bal", "bc", "bcc", "bcs", "beq", "bne", "bgt",
    "bge", "blt", "ble", "bhi", "bls", "bvs", "bvc", "bmi", "bpl",
    "bhs", "blo", "br", "bra", "brw", "bl", "blx", "bx", "bxj",
    "jmp", "ljmp", "jmpq", "call", "callq",
}

BRANCH_TYPE_PREFIXES = ("j", "loop", "cbz", "cbnz", "tbz", "tbnz")

# Populated from ida_idp.ph_get_instruc(); keys are decoded insn_t.itype values.
INSTRUCTION_NAMES = {}
XOR_ITYPES = set()
MIX_ITYPES = set()
SHIFT_ROTATE_ITYPES = set()
BRANCH_ITYPES = set()


# ---------------------------------------------------------------------------
#   Instruction type discovery / decoding
# ---------------------------------------------------------------------------

def _normalise_type_name(name):
    """Normalise a processor-table instruction identifier."""
    return str(name or "").lower().replace(" ", "")


def _build_instruction_type_sets():
    """Build architecture-specific itype sets from the active IDP module.

    IDA's instruction codes are processor-module-specific. ph_get_instruc_start()
    gives the first code and ph_get_instruc() returns its (name, feature) table.
    For each table entry, its itype is start + entry_index.
    """
    global INSTRUCTION_NAMES, XOR_ITYPES, MIX_ITYPES
    global SHIFT_ROTATE_ITYPES, BRANCH_ITYPES

    try:
        first_itype = int(ida_idp.ph_get_instruc_start())
        last_itype = int(ida_idp.ph_get_instruc_end())
        instruction_table = ida_idp.ph_get_instruc()
    except Exception as exc:
        raise RuntimeError(
            "Cannot read the active processor instruction table via ida_idp: %s" % exc
        )

    if not instruction_table:
        raise RuntimeError("The active processor instruction table is empty")

    # In the SDK, instruc_end is the end of the processor's instruction-code
    # range. Be tolerant of modules whose exposed table/range length differs.
    range_size = max(0, last_itype - first_itype)
    usable_count = min(len(instruction_table), range_size or len(instruction_table))

    names = {}
    for index in range(usable_count):
        entry = instruction_table[index]
        try:
            type_name = _normalise_type_name(entry[0])
        except Exception:
            continue
        if type_name:
            names[first_itype + index] = type_name

    if not names:
        raise RuntimeError("Could not map processor instruction types to names")

    def types_with_prefixes(prefixes, exact=()):
        exact = set(exact)
        result = set()
        for itype, type_name in names.items():
            if type_name in exact or type_name.startswith(prefixes):
                result.add(itype)

        return result

    INSTRUCTION_NAMES = names
    XOR_ITYPES = types_with_prefixes(XOR_TYPE_PREFIXES)
    MIX_ITYPES = types_with_prefixes(MIX_TYPE_PREFIXES)
    SHIFT_ROTATE_ITYPES = types_with_prefixes(SHIFT_ROTATE_TYPE_PREFIXES)
    BRANCH_ITYPES = types_with_prefixes(BRANCH_TYPE_PREFIXES, BRANCH_TYPE_EXACT)

    if not XOR_ITYPES:
        proc_name = "unknown"
        try:
            proc_name = str(ida_idp.ph_get_id())
        except Exception:
            pass
        raise RuntimeError(
            "No XOR-like instruction types identified for processor '%s'. "
            "Its table may use different instruction names." % proc_name
        )


def _decode_instruction(ea):
    """Decode ea without changing the database; return insn_t or None."""
    insn = ida_ua.insn_t()
    try:
        size = ida_ua.decode_insn(insn, ea)
    except Exception:
        return None

    return insn if size > 0 else None


def _instruction_type_name(insn):
    """Return the processor table label (Debug)."""
    return INSTRUCTION_NAMES.get(int(insn.itype), "itype_%d" % int(insn.itype))


def _explicit_operands(insn):
    """Return decoded operands up to the first o_void operand."""
    result = []
    for index in range(8):  # insn_t contains eight operand slots in IDA 9.x
        try:
            op = insn.ops[index]
        except Exception:
            break
        if op.type == ida_ua.o_void:
            break
        result.append(op)

    return result


def _operand_register(op):
    """Return the numeric register ID for an o_reg operand, else None."""
    if op is not None and op.type == ida_ua.o_reg:
        return int(op.reg)

    return None


def _is_self_xor(insn):
    """Detect register self-XOR / XOR-with-identical-sources zeroing forms.

    Two operands: dst ^= src, so dst == src clears the destination.
    Three operands: dst = src1 XOR src2, so src1 == src2 clears the destination.
    Only decoded register operands are considered; printed operand strings are
    deliberately not used for this test.
    """
    ops = _explicit_operands(insn)

    if len(ops) == 2:
        dst = _operand_register(ops[0])
        src = _operand_register(ops[1])
        return dst is not None and src is not None and dst == src

    if len(ops) == 3:
        src1 = _operand_register(ops[1])
        src2 = _operand_register(ops[2])
        return src1 is not None and src2 is not None and src1 == src2

    # Do not guess for unusual instruction forms (e.g. four-input EOR3).
    return False


def _is_backward_branch(ea, insn, func_start):
    """Detect a direct, typed branch to an earlier address in this function."""
    if int(insn.itype) not in BRANCH_ITYPES:
        return False

    ops = _explicit_operands(insn)
    if not ops:
        return False

    direct_types = set()
    for attr in ("o_near", "o_far"):
        if hasattr(ida_ua, attr):
            direct_types.add(getattr(ida_ua, attr))
    if not direct_types or ops[0].type not in direct_types:
        return False

    try:
        target = int(ops[0].addr)
    except Exception:
        return False

    return func_start <= target < ea


def _disasm(ea):
    """Format an instruction for UI display."""
    try:
        line = idc.generate_disasm_line(ea, 0)
        if line:
            return ida_lines.tag_remove(line).strip()
    except Exception:
        pass

    return "instruction at 0x%X" % ea


def _function_name(func_ea):
    try:
        return idc.get_func_name(func_ea) or ("sub_%X" % func_ea)
    except Exception:
        return "sub_%X" % func_ea


# ---------------------------------------------------------------------------
#   Scoring
# ---------------------------------------------------------------------------

def _score_function(useful_count, mix_count, rotate_count,
                    back_edges, useful_dst_registers, insn_count):
    """Return heuristic score for a function"""
    # A function containing only zeroing XORs should not score as an XOR-based
    # encoding candidate, regardless of how many unrelated shifts/loops it has.
    if useful_count <= 0:
        return 0

    if useful_count == 1:
        score = 1
    elif useful_count == 2:
        score = 2
    elif useful_count <= 4:
        score = 3
    elif useful_count <= 7:
        score = 4
    else:
        score = 5

    if mix_count >= 4:
        score += 2
    if mix_count >= 8:
        score += 1

    if back_edges:
        score += 2
    if back_edges >= 3:
        score += 1

    if rotate_count >= 2:
        score += 1

    # Reusing a destination register across non-zeroing XOR instructions is a
    # weak accumulator/round-function hint.
    dst_counts = collections.Counter(useful_dst_registers)
    if dst_counts and max(dst_counts.values()) >= 2:
        score += 1

    if insn_count and useful_count >= 3 and (useful_count / float(insn_count)) >= 0.08:
        score += 1

    return score


def _rating(score, useful_count):
    if useful_count >= 3 and score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
#   Scan and rank
# ---------------------------------------------------------------------------

def scan_xor_functions():
    results = []
    total_functions = 0
    total_xor_insns = 0
    total_self_xor_insns = 0

    for func_ea in idautils.Functions():
        total_functions += 1
        xor_eas = []
        useful_xor_eas = []
        self_xor_eas = []
        back_edge_eas = []
        useful_dst_registers = []
        mix_count = 0
        rotate_count = 0
        insn_count = 0

        try:
            for ea in idautils.FuncItems(func_ea):
                insn = _decode_instruction(ea)
                if insn is None:
                    continue

                insn_count += 1
                itype = int(insn.itype)

                if itype in MIX_ITYPES:
                    mix_count += 1
                if itype in SHIFT_ROTATE_ITYPES:
                    rotate_count += 1
                if _is_backward_branch(ea, insn, func_ea):
                    back_edge_eas.append(ea)

                if itype not in XOR_ITYPES:
                    continue

                xor_eas.append(ea)
                if _is_self_xor(insn):
                    self_xor_eas.append(ea)
                else:
                    useful_xor_eas.append(ea)
                    dst_register = None
                    ops = _explicit_operands(insn)
                    if ops:
                        dst_register = _operand_register(ops[0])
                    if dst_register is not None:
                        useful_dst_registers.append(dst_register)

        except Exception as exc:
            print("[XORFinder] Warning: failed to scan 0x%X: %s" % (func_ea, exc))
            continue

        if not xor_eas:
            continue

        total_xor_insns += len(xor_eas)
        total_self_xor_insns += len(self_xor_eas)

        score = _score_function(
            len(useful_xor_eas), mix_count, rotate_count,
            len(back_edge_eas), useful_dst_registers, insn_count
        )

        first_ea = useful_xor_eas[0] if useful_xor_eas else xor_eas[0]
        results.append({
            "func_ea": func_ea,
            "name": _function_name(func_ea),
            "xor_eas": xor_eas,
            "useful_xor_eas": useful_xor_eas,
            "self_xor_eas": self_xor_eas,
            "back_edge_eas": back_edge_eas,
            "insn_count": insn_count,
            "mix_count": mix_count,
            "rotate_count": rotate_count,
            "score": score,
            "rating": _rating(score, len(useful_xor_eas)),
            "first_ea": first_ea,
            "sample": _disasm(first_ea),
        })

    results.sort(key=lambda item: (
        item["score"], len(item["useful_xor_eas"]), len(item["xor_eas"])
    ), reverse=True)

    return results, total_functions, total_xor_insns, total_self_xor_insns


# ---------------------------------------------------------------------------
#   IDA UI chooser
# ---------------------------------------------------------------------------

class XORResultsChooser(ida_kernwin.Choose):
    def __init__(self, results):
        self.results = results
        columns = [
            ["Function", 28],
            ["Function EA", 12],
            ["XORs", 5],
            ["Useful", 6],
            ["Zeroing", 7],
            ["Back edges", 10],
            ["Score", 5],
            ["Rating", 9],
            ["First XOR / sample", 42],
        ]
        super(XORResultsChooser, self).__init__(WINDOW_TITLE, columns, flags=0)

    def OnGetSize(self):
        return len(self.results)

    def OnGetLine(self, n):
        item = self.results[n]
        return [
            item["name"],
            "%X" % item["func_ea"],
            str(len(item["xor_eas"])),
            str(len(item["useful_xor_eas"])),
            str(len(item["self_xor_eas"])),
            str(len(item["back_edge_eas"])),
            str(item["score"]),
            item["rating"],
            "%X: %s" % (item["first_ea"], item["sample"]),
        ]

    def OnSelectLine(self, n):
        if 0 <= n < len(self.results):
            ida_kernwin.jumpto(self.results[n]["first_ea"])

        return (ida_kernwin.Choose.NOTHING_CHANGED, n)


# Keep a global reference so Python does not garbage-collect the chooser.
_xor_finder_chooser = None


def main():
    global _xor_finder_chooser

    try:
        _build_instruction_type_sets()
    except Exception as exc:
        message = "[XORFinder] Could not initialise instruction types: %s" % exc
        print(message)
        ida_kernwin.msg(message + "\n")
        return

    print("[XORFinder] Processor instruction types loaded: %d" % len(INSTRUCTION_NAMES))
    print("[XORFinder] XOR-like itypes: %d" % len(XOR_ITYPES))
    print("[XORFinder] Scanning analyzed functions with decode_insn()...")

    results, total_functions, total_xor_insns, total_self_xor_insns = scan_xor_functions()

    print("[XORFinder] Functions scanned: %d" % total_functions)
    print("[XORFinder] Functions containing XOR-like instructions: %d" % len(results))
    print("[XORFinder] XOR-like instructions found: %d" % total_xor_insns)
    print("[XORFinder] Self-XOR/zeroing instructions: %d" % total_self_xor_insns)

    if not results:
        print("[XORFinder] No XOR-like instruction types found in analyzed functions.")
        ida_kernwin.msg("[XORFinder] No XOR-like instruction types found.\n")
        return

    print("[XORFinder] Top candidates:")
    for item in results[:20]:
        print("  %s @ 0x%X | XOR=%d useful=%d zeroing=%d loops=%d score=%d (%s)" % (
            item["name"], item["func_ea"], len(item["xor_eas"]),
            len(item["useful_xor_eas"]), len(item["self_xor_eas"]),
            len(item["back_edge_eas"]), item["score"], item["rating"]
        ))

    print("[XORFinder] Type-based heuristic; inspect candidates before drawing conclusions.")
    _xor_finder_chooser = XORResultsChooser(results)
    _xor_finder_chooser.Show(modal=False)


if __name__ == "__main__":
    main()
