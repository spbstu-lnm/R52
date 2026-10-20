"""Timing Finder for IDA Pro 9.3 (IDAPython).

Finds RDTSC/RDTSCP, calls to timing APIs (directly or via import thunks)
and nearby pairs of such sites within one function (a heuristic).
Usage: File -> Script file...
"""

import re

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_lines
import ida_nalt
import ida_segment
import idautils
import idc


# ---------------------------------------------------------------------------
#   Configuration
# ---------------------------------------------------------------------------

TITLE = "Timing Finder"
LOG_TAG = "[Timing]"

SEARCH_RDTSCP = True
ADD_COMMENTS = False            # True = annotate found sites in the database
MAX_PAIR_DISTANCE = 0x1000      # max distance (bytes) for a "pair" of sites
TIMING_APIS = ("GetTickCount", "GetTickCount64")   # extend as needed

# Also matches decorated names: __imp_X, j_X, _X@0, KERNEL32_X.
API_NAME_RE = re.compile(
    r"(?:^|[^a-z0-9])(?:%s)(?:@\d+)?$" % "|".join(map(re.escape, TIMING_APIS)),
    re.IGNORECASE,
)
CALL_MNEMONICS = {"call", "callq", "bl", "blx", "blr", "jal", "jalr", "lcall"}
JUMP_MNEMONICS = {"jmp", "jmpq", "b", "br", "bx"}
COMMENT_MARKER = LOG_TAG

COLUMNS = [
    ["Kind", 14],
    ["Function", 28],
    ["Detail", 40],
    ["Disassembly", 44],
]

_chooser = None  # keep a reference while the window is open


# ---------------------------------------------------------------------------
#   Helpers
# ---------------------------------------------------------------------------

class ScanCancelled(Exception):
    pass


def log(message):
    ida_kernwin.msg("%s %s\n" % (LOG_TAG, message))


def disasm(ea):
    line = idc.generate_disasm_line(ea, 0) or ""
    return ida_lines.tag_remove(line).strip()


def func_name(ea):
    return idc.get_func_name(ea) or "<no function>"


def func_start(ea):
    func = ida_funcs.get_func(ea)
    return func.start_ea if func else None


def mnemonic(ea):
    return (idc.print_insn_mnem(ea) or "").lower()


def is_code(ea):
    return ea != idc.BADADDR and ida_bytes.is_code(ida_bytes.get_flags(ea))


def is_call(mnem):
    return mnem in CALL_MNEMONICS or mnem.startswith("call")


def is_jump(mnem):
    return mnem in JUMP_MNEMONICS or mnem.startswith("jmp")


def iter_insns():
    """Yield code heads of executable segments; raise ScanCancelled on Cancel."""
    count = 0
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None:
            continue
        executable = (seg.perm & ida_segment.SEGPERM_EXEC) or seg.type == ida_segment.SEG_CODE
        if not executable:
            continue
        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
            count += 1
            if count % 4096 == 0 and ida_kernwin.user_cancelled():
                raise ScanCancelled()
            if ida_bytes.is_code(ida_bytes.get_flags(ea)):
                yield ea


def add_comment(ea, text):
    if not ADD_COMMENTS:
        return
    old = idc.get_cmt(ea, False) or ""
    if COMMENT_MARKER in old and text in old:
        return
    idc.set_cmt(ea, (old + " | " if old else "") + COMMENT_MARKER + " " + text, False)


# ---------------------------------------------------------------------------
#   Scan
# ---------------------------------------------------------------------------

def scan_rdtsc():
    """Return {ea: MNEMONIC} for RDTSC/RDTSCP instructions."""
    wanted = {"rdtsc", "rdtscp"} if SEARCH_RDTSCP else {"rdtsc"}
    found = {}
    for ea in iter_insns():
        mnem = mnemonic(ea)
        if mnem in wanted:
            found[ea] = mnem.upper()
            add_comment(ea, "%s: possible cycle-counter measurement" % mnem.upper())
    return found


def collect_api_targets():
    """Return {ea: {labels}} for named/imported timing APIs."""
    targets = {}

    def add(ea, label):
        if ea != idc.BADADDR:
            targets.setdefault(ea, set()).add(label)

    for ea, name in idautils.Names():
        if API_NAME_RE.search(name or ""):
            add(ea, name)

    for index in range(ida_nalt.get_import_module_qty()):
        dll = ida_nalt.get_import_module_name(index) or "<unknown DLL>"

        def callback(ea, name, ordinal, dll=dll):
            if API_NAME_RE.search(name or ""):
                add(ea, "%s!%s" % (dll, name))
            return True

        ida_nalt.enum_import_names(index, callback)

    return targets


def scan_api_refs(targets):
    """Return ({call ea: labels}, {other ref ea: labels}, thunk count)."""
    calls, refs, thunks = {}, {}, {}

    for target, labels in targets.items():
        for xref in idautils.XrefsTo(target, 0):
            src = xref.frm
            if not is_code(src):
                continue
            mnem = mnemonic(src)
            func = ida_funcs.get_func(src)
            for label in labels:
                if is_call(mnem):
                    calls.setdefault(src, set()).add(label)
                    add_comment(src, "call to %s" % label)
                else:
                    refs.setdefault(src, set()).add(label)
                    add_comment(src, "reference to %s" % label)
                # An import thunk is a function that starts with a JMP to the API.
                if func and func.start_ea == src and is_jump(mnem):
                    thunks.setdefault(src, set()).add(label)

    # One level up: calls to the thunks.
    for thunk, labels in thunks.items():
        thunk_name = idc.get_name(thunk) or ("thunk_%X" % thunk)
        for xref in idautils.XrefsTo(thunk, 0):
            src = xref.frm
            if is_code(src) and is_call(mnemonic(src)):
                for label in labels:
                    calls.setdefault(src, set()).add("%s via %s" % (label, thunk_name))
                    add_comment(src, "call to %s via thunk %s" % (label, thunk_name))

    return calls, refs, len(thunks)


def find_pairs(addresses):
    """Return [(left, right, distance)] for neighbours within one function."""
    by_func = {}
    for ea in sorted(addresses):
        start = func_start(ea)
        if start is not None:
            by_func.setdefault(start, []).append(ea)

    pairs = []
    for eas in by_func.values():
        for left, right in zip(eas, eas[1:]):
            if right - left <= MAX_PAIR_DISTANCE:
                pairs.append((left, right, right - left))
    return sorted(pairs)


def make_row(ea, kind, detail):
    return (ea, [kind, func_name(ea), detail, disasm(ea)])


def scan():
    rows = []
    stats = {"targets": 0, "thunks": 0}

    ida_kernwin.clr_cancelled()
    ida_kernwin.show_wait_box("NODELAY\nSearching for timing measurement sites...")
    try:
        rdtsc = scan_rdtsc()
        targets = collect_api_targets()
        calls, refs, thunk_count = scan_api_refs(targets)
        stats.update(targets=len(targets), thunks=thunk_count)

        rows += [make_row(ea, "RDTSC", m) for ea, m in rdtsc.items()]
        rows += [make_row(ea, "API call", ", ".join(sorted(l))) for ea, l in calls.items()]
        rows += [make_row(ea, "API ref", ", ".join(sorted(l))) for ea, l in refs.items()]

        for kind, eas in (("Pair (RDTSC)", rdtsc), ("Pair (API)", calls)):
            for left, right, dist in find_pairs(eas):
                rows.append(make_row(left, kind, "-> 0x%X (distance 0x%X)" % (right, dist)))
    except ScanCancelled:
        log("Scan cancelled, results are partial.")
    finally:
        ida_kernwin.hide_wait_box()

    rows.sort(key=lambda row: (row[0], row[1][0]))
    return rows, stats


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


def show_results(rows):
    global _chooser
    if not rows:
        log("Nothing found.")
        return
    _chooser = ResultChooser(TITLE, COLUMNS, rows)
    _chooser.Show()


# ---------------------------------------------------------------------------
#   Main
# ---------------------------------------------------------------------------

def main():
    rows, stats = scan()
    log("Rows: %d | API targets: %d | thunk candidates: %d" %
        (len(rows), stats["targets"], stats["thunks"]))
    log("Pairs are only a proximity heuristic; verify the control flow.")
    show_results(rows)


if __name__ == "__main__":
    main()
