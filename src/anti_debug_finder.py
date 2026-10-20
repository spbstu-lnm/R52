"""PEB Access Finder for IDA Pro 9.3 (IDAPython).

Finds:
  * reads of the TEB.Peb slot (FS:[30h] / GS:[60h]);
  * accesses through registers derived from that pointer (CFG-based tracking);
  * WinAPI/NTAPI calls related to the PEB, debugger checks and the loader;
  * strings with API names (candidates for GetProcAddress resolution).

An API hit alone is not proof of a raw PEB read. The database is not modified.
Usage: File -> Script file...
"""

import re

import ida_bytes
import ida_funcs
import ida_gdl
import ida_kernwin
import ida_lines
import ida_segment
import idautils
import idc


# ---------------------------------------------------------------------------
#   Configuration
# ---------------------------------------------------------------------------

TITLE = "PEB Access Finder"
LOG_TAG = "[PEB]"

# Direct reads of the slot:  PEB_PTR_LOAD / PEB_SLOT_READ / PEB_SLOT_RMW.
# Via derived registers:     PEB_FIELD_READ / PEB_FIELD_RMW.
# Category -> (API names, short explanation of the evidence).
API_CATEGORIES = {
    "WINAPI_PEB_ACCESS": (
        ("RtlGetCurrentPeb",),
        "returns the PEB pointer (strongest API-level indicator)"),
    "WINAPI_TEB_ACCESS": (
        ("RtlGetCurrentTeb", "NtCurrentTeb"),
        "returns the TEB, which holds the PEB pointer"),
    "WINAPI_PEB_QUERY": (
        ("NtQueryInformationProcess", "ZwQueryInformationProcess"),
        "class 0 returns PebBaseAddress, class 7 is a debug-port check"),
    "WINAPI_ANTI_DEBUG": (
        ("IsDebuggerPresent", "CheckRemoteDebuggerPresent",
         "NtSetInformationThread", "ZwSetInformationThread"),
        "debugger check / ThreadHideFromDebugger"),
    "WINAPI_DEBUG_QUERY": (
        ("NtQuerySystemInformation", "ZwQuerySystemInformation",
         "RtlQueryProcessDebugInformation"),
        "system/process debug information queries"),
    "WINAPI_DEBUG_RELATED": (
        ("OutputDebugStringA", "OutputDebugStringW"),
        "sends a string to the debugger"),
    "WINAPI_LOADER": (
        ("GetModuleHandleA", "GetModuleHandleW", "GetModuleHandleExA", "GetModuleHandleExW",
         "LdrGetDllHandle", "LdrGetDllHandleEx", "LdrEnumerateLoadedModules", "LdrLoadDll",
         "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"),
        "loader state (PEB.Ldr); weak indicator"),
    "WINAPI_API_RESOLUTION": (
        ("GetProcAddress", "LdrGetProcedureAddress"),
        "dynamic API resolution; may hide further calls"),
    "WINAPI_PROCESS_PARAMETERS": (
        ("GetCommandLineA", "GetCommandLineW"),
        "process parameters (PEB.ProcessParameters); weak indicator"),
}

# Registers are tracked by family, so EAX/AX/AL count as RAX.
_FAMILIES = {
    "rax": "rax eax ax al ah", "rbx": "rbx ebx bx bl bh",
    "rcx": "rcx ecx cx cl ch", "rdx": "rdx edx dx dl dh",
    "rsi": "rsi esi si sil", "rdi": "rdi edi di dil",
    "rbp": "rbp ebp bp bpl", "rsp": "rsp esp sp spl",
}
for _n in range(8, 16):
    _FAMILIES["r%d" % _n] = "r{0} r{0}d r{0}w r{0}b".format(_n)
REG_FAMILY = {alias: family for family, aliases in _FAMILIES.items() for alias in aliases.split()}

REG_TOKEN_RE = re.compile(
    r"\b(" + "|".join(sorted(REG_FAMILY, key=len, reverse=True)) + r")\b", re.IGNORECASE)

# IDA prints fs:30h, fs:[30h], large fs:30h, gs:qword ptr [60h], ...
SEGMENT_SLOT_RE = re.compile(
    r"\b(fs|gs)\s*:\s*(?:(?:byte|word|dword|qword|tbyte|xmmword|ymmword|zmmword)\s+ptr\s*)?"
    r"\[?\s*(0x[0-9a-f]+|[0-9a-f]+h|\d+)\b(?!\s*[-+*])",
    re.IGNORECASE,
)
API_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_@$?.!]*")
API_PREFIXES = ("__imp_", "_imp_", "imp_", "j_")

# Instructions whose first operand is not written.
NO_DEST_WRITE = {
    "cmp", "test", "push", "call", "jmp", "ret", "retn", "retf", "iret", "iretd", "iretq",
    "nop", "pause", "int", "int1", "int3", "into", "syscall", "sysenter", "sysexit", "ud2",
    "bt", "prefetch", "prefetchnta", "prefetcht0", "prefetcht1", "prefetcht2",
}
# Read-modify-write instructions (first operand is read and written).
RMW_MNEMONICS = {
    "add", "adc", "sub", "sbb", "and", "or", "xor", "inc", "dec", "neg", "not",
    "shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr", "xchg", "xadd",
    "cmpxchg", "bts", "btr", "btc", "shld", "shrd",
}
CALL_CLOBBERED = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
COPY_MNEMONICS = {"mov", "movabs"}
MAX_OPERANDS = 8

COLUMNS = [
    ["Category", 26],
    ["Function", 28],
    ["Detail", 60],
    ["Disassembly", 40],
]

# lowercase API name -> (canonical name, category)
API_LOOKUP = {
    name.lower(): (name, category)
    for category, (names, _) in API_CATEGORIES.items() for name in names
}

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


def is_code(ea):
    return ida_bytes.is_code(ida_bytes.get_flags(ea))


def iter_insns(start_ea=None, end_ea=None):
    """Yield code heads (executable segments by default); raise ScanCancelled on Cancel."""
    count = 0
    ranges = [(start_ea, end_ea)] if start_ea is not None else []
    if not ranges:
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg is not None and ((seg.perm & ida_segment.SEGPERM_EXEC)
                                    or seg.type == ida_segment.SEG_CODE):
                ranges.append((seg.start_ea, seg.end_ea))
    for start, end in ranges:
        for ea in idautils.Heads(start, end):
            count += 1
            if count % 4096 == 0 and ida_kernwin.user_cancelled():
                raise ScanCancelled()
            if is_code(ea):
                yield ea


def get_instruction(ea):
    """Return (mnemonic, [operand texts]); mnemonic is '' for non-instructions."""
    mnem = (idc.print_insn_mnem(ea) or "").lower().strip()
    if not mnem:
        return "", []
    ops = []
    for index in range(MAX_OPERANDS):
        text = idc.print_operand(ea, index)
        if not text:
            break
        ops.append(text.strip())
    return mnem, ops


def reg_family(operand):
    return REG_FAMILY.get((operand or "").strip().lower())


def memory_registers(operand):
    """Register families used inside [...] of an operand."""
    text = operand or ""
    left, right = text.find("["), text.rfind("]")
    if left < 0 or right <= left:
        return set()
    return {REG_FAMILY[t.lower()] for t in REG_TOKEN_RE.findall(text[left + 1:right])}


def memory_access_mode(mnem, index):
    """'R', 'R/W', or None when the operand is only written (or is LEA)."""
    if mnem == "lea":
        return None
    if index == 0:
        if mnem.startswith(("mov", "set")) or mnem == "pop":
            return None
        if mnem in RMW_MNEMONICS:
            return "R/W"
    return "R"


def peb_slot(operand):
    """Return (segment, offset) for FS:[30h] / GS:[60h], else None."""
    match = SEGMENT_SLOT_RE.search(operand or "")
    if not match:
        return None
    segment, token = match.group(1).lower(), match.group(2).lower()
    try:
        if token.startswith("0x"):
            offset = int(token, 16)
        elif token.endswith("h"):
            offset = int(token[:-1], 16)
        else:
            offset = int(token, 10)
    except ValueError:
        return None
    if (segment, offset) in (("fs", 0x30), ("gs", 0x60)):
        return segment, offset
    return None


def is_peb_ptr_load(mnem, ops):
    """mov reg, fs:[30h] and similar."""
    return (mnem in COPY_MNEMONICS and len(ops) > 1 and reg_family(ops[0]) is not None
            and any(peb_slot(op) for op in ops[1:]))


def normalize_api(token):
    """Normalize __imp_Foo, _Foo@8, j_Foo, KERNEL32_Foo, Dll!Foo to 'foo'."""
    value = (token or "").strip().split("!")[-1].lower()
    value = re.sub(r"@\d+$", "", value)
    for prefix in API_PREFIXES:
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    value = value.lstrip("_")
    if value not in API_LOOKUP:
        for api in API_LOOKUP:
            if value.endswith("_" + api):
                return api
    return value


def api_matches(text):
    """Return {canonical API name: category} for API names found in text."""
    found = {}
    for token in API_TOKEN_RE.findall(text or ""):
        entry = API_LOOKUP.get(normalize_api(token))
        if entry:
            found[entry[0]] = entry[1]
    return found


# ---------------------------------------------------------------------------
#   Scan
# ---------------------------------------------------------------------------

class Findings(object):
    """Unique (ea, category, detail) records."""

    def __init__(self):
        self.items = set()

    def add(self, ea, category, detail):
        self.items.add((ea, category, detail))


def scan_instructions(findings):
    """One pass: direct PEB slot reads and API calls/jumps by disassembly text."""
    for ea in iter_insns():
        mnem, ops = get_instruction(ea)
        if not mnem:
            continue

        for index, op in enumerate(ops):
            slot = peb_slot(op)
            mode = memory_access_mode(mnem, index) if slot else None
            if mode is None:
                continue
            if index > 0 and is_peb_ptr_load(mnem, ops):
                category = "PEB_PTR_LOAD"
            else:
                category = "PEB_SLOT_RMW" if mode == "R/W" else "PEB_SLOT_READ"
            findings.add(ea, category, "operand %d=%s (%s:[0x%X], %s)" %
                         (index, op, slot[0].upper(), slot[1], mode))

        if mnem in ("call", "jmp"):
            for api, category in api_matches(disasm(ea)).items():
                findings.add(ea, category, "API %s" % api)


def writes_first_operand(mnem):
    return mnem not in NO_DEST_WRITE and not mnem.startswith(("j", "loop"))


def step(state, mnem, ops):
    """Update the set of registers that may hold a PEB-derived value."""
    if mnem == "call":
        state.difference_update(CALL_CLOBBERED)
        return
    dest = reg_family(ops[0]) if ops else None
    if not dest:
        return

    if (is_peb_ptr_load(mnem, ops)
            or (mnem in COPY_MNEMONICS and len(ops) > 1 and reg_family(ops[1]) in state)
            or (mnem == "lea" and any(memory_registers(op) & state for op in ops[1:]))):
        state.add(dest)
    elif mnem.startswith("cmov"):
        if len(ops) > 1 and reg_family(ops[1]) in state:
            state.add(dest)     # may keep the old value, so no discard
    elif writes_first_operand(mnem):
        state.discard(dest)


def analyze_function(func, findings):
    """Forward may-analysis over the CFG; report accesses via tracked registers."""
    blocks = list(ida_gdl.FlowChart(func))
    decoded = {}
    for block in blocks:
        decoded[block.id] = [(ea,) + get_instruction(ea)
                             for ea in iter_insns(block.start_ea, block.end_ea)]

    # Without a direct PEB pointer load the tracked state stays empty.
    if not any(is_peb_ptr_load(mnem, ops) for insns in decoded.values()
               for _, mnem, ops in insns if mnem):
        return

    ids = {block.id for block in blocks}
    preds = {block.id: [p.id for p in block.preds() if p.id in ids] for block in blocks}
    in_state = {block.id: set() for block in blocks}
    out_state = {block.id: set() for block in blocks}

    changed = True
    while changed:     # finite lattice (register families): reaches a fixed point
        changed = False
        for block in blocks:
            incoming = set().union(*(out_state[p] for p in preds[block.id]))
            state = set(incoming)
            for _, mnem, ops in decoded[block.id]:
                if mnem:
                    step(state, mnem, ops)
            if incoming != in_state[block.id] or state != out_state[block.id]:
                in_state[block.id], out_state[block.id] = incoming, state
                changed = True

    for block in blocks:
        state = set(in_state[block.id])
        for ea, mnem, ops in decoded[block.id]:
            if not mnem:
                continue
            for index, op in enumerate(ops):
                mode = memory_access_mode(mnem, index)
                bases = memory_registers(op) & state if mode else None
                if bases:
                    category = "PEB_FIELD_READ" if mode == "R" else "PEB_FIELD_RMW"
                    findings.add(ea, category, "operand %d=%s; PEB-derived=%s; mode=%s" %
                                 (index, op, ",".join(sorted(bases)), mode))
            step(state, mnem, ops)


def scan_derived_accesses(findings):
    for func_ea in idautils.Functions():
        if ida_kernwin.user_cancelled():
            raise ScanCancelled()
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        try:
            analyze_function(func, findings)
        except ScanCancelled:
            raise
        except Exception as exc:
            log("Cannot analyze 0x%X: %s" % (func_ea, exc))


def scan_named_api_xrefs(findings):
    """Calls/jumps to named imports and thunks (disassembly may omit the name)."""
    for name_ea, name in idautils.Names():
        for api, category in api_matches(name).items():
            for xref in idautils.XrefsTo(name_ea, 0):
                site = xref.frm
                if is_code(site) and idc.print_insn_mnem(site).lower() in ("call", "jmp"):
                    findings.add(site, category, "API %s" % api)


def scan_api_strings(findings):
    """Code references to strings that are exact API names (GetProcAddress cases)."""
    for item in idautils.Strings():
        value = str(item).strip().strip("\x00")
        entry = API_LOOKUP.get(normalize_api(value))
        if not entry:
            continue
        for ref in idautils.DataRefsTo(item.ea):
            if is_code(ref):
                findings.add(ref, "WINAPI_API_STRING",
                             "string %r (candidate dynamic API name: %s); "
                             "check for a nearby GetProcAddress call" % (value, entry[0]))


def scan():
    findings = Findings()
    ida_kernwin.clr_cancelled()
    ida_kernwin.show_wait_box("NODELAY\nSearching for PEB accesses and related APIs...")
    try:
        scan_instructions(findings)
        scan_derived_accesses(findings)
        scan_named_api_xrefs(findings)
        scan_api_strings(findings)
    except ScanCancelled:
        log("Scan cancelled, results are partial.")
    finally:
        ida_kernwin.hide_wait_box()

    rows = []
    for ea, category, detail in sorted(findings.items):
        rows.append((ea, [category, func_name(ea), detail, disasm(ea)]))
    return rows


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
    rows = scan()
    log("Findings: %d at %d address(es)." %
        (len(rows), len({ea for ea, _ in rows})))
    show_results(rows)


if __name__ == "__main__":
    main()
