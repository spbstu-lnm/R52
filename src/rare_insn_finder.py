"""Rare Instruction Finder for IDA Pro 9.3 (IDAPython).

Lists rare, privileged and anti-debug-related instructions.
Usage: File -> Script file...
"""

import re

import ida_bytes
import ida_kernwin
import ida_lines
import ida_segment
import idautils
import idc


# ---------------------------------------------------------------------------
#   Configuration
# ---------------------------------------------------------------------------

TITLE = "Rare Instruction Finder"
LOG_TAG = "[RareInsn]"

RARE_MNEMONICS = {
    "cpuid": "CPU identification",
    "rdtsc": "Timing / anti-debug",
    "rdtscp": "Timing / anti-debug",
    "rdpmc": "Performance counter",
    "icebp": "ICEBP / anti-debug",
    "int1": "ICEBP / anti-debug",
    "int3": "Breakpoint",
    "ud2": "Invalid-opcode trap",
    "syscall": "System call",
    "sysret": "System call",
    "sysenter": "System call",
    "sysexit": "System call",
    "vmcall": "Virtualization",
    "vmmcall": "Virtualization",
    "vmrun": "Virtualization",
    "hlt": "Privileged / halt",
    "cli": "Interrupt control",
    "sti": "Interrupt control",
    "invd": "Cache control",
    "wbinvd": "Cache control",
    "invlpg": "TLB control",
    "xsetbv": "Extended CPU state",
    "xgetbv": "Extended CPU state",
    "smsw": "System state",
    "sgdt": "Descriptor table",
    "sidt": "Descriptor table",
    "sldt": "System state",
    "str": "System state",
    "lldt": "System state",
    "ltr": "System state",
    "clts": "System state",
    "swapgs": "System state",
    "rsm": "System state",
    "lar": "Protection check",
    "lsl": "Protection check",
    "verr": "Protection check",
    "verw": "Protection check",
    "lss": "Stack segment load (LSS)",
    "monitor": "Power / wait hint",
    "mwait": "Power / wait hint",
    "umonitor": "Power / wait hint",
    "umwait": "Power / wait hint",
    "tpause": "Power / wait hint",
    "rdmsr": "MSR access",
    "wrmsr": "MSR access",
    "rdrand": "Hardware random",
    "rdseed": "Hardware random",
    "xabort": "Transactional memory",
    "xbegin": "Transactional memory",
}

MAX_OPERANDS = 8
SPECIAL_REG_RE = re.compile(r"^(cr|dr|tr)\d+$")
MEMORY_OPERAND_TYPES = (idc.o_mem, idc.o_phrase, idc.o_displ)

COLUMNS = [
    ["Mnemonic", 10],
    ["Category", 26],
    ["Disassembly", 44],
    ["Bytes", 22],
    ["Function", 28],
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


def raw_bytes(ea):
    data = ida_bytes.get_bytes(ea, idc.get_item_size(ea)) or b""
    return bytes(data).hex(" ").upper()


# ---------------------------------------------------------------------------
#   Scan
# ---------------------------------------------------------------------------

def match_insn(ea, mnem):
    """Return a category string if the instruction is interesting, else None."""
    # INT 2Dh is a known Windows anti-debug trick.
    if (mnem == "int" and idc.get_operand_type(ea, 0) == idc.o_imm
            and idc.get_operand_value(ea, 0) == 0x2D):
        return "INT 2D / anti-debug"

    if mnem in RARE_MNEMONICS:
        return RARE_MNEMONICS[mnem]

    for idx in range(MAX_OPERANDS):
        op_type = idc.get_operand_type(ea, idx)
        if op_type == idc.o_void:
            break
        text = (idc.print_operand(ea, idx) or "").lower().replace(" ", "")
        if op_type == idc.o_reg:
            if text == "ss":
                return "SS register use"
            if SPECIAL_REG_RE.match(text):
                return "Control / debug / test register"
        elif op_type in MEMORY_OPERAND_TYPES and "ss:" in text:
            return "SS segment override"

    return None


def scan():
    rows = []
    ida_kernwin.clr_cancelled()
    ida_kernwin.show_wait_box("NODELAY\nScanning for rare instructions...")
    try:
        for ea in iter_insns():
            mnem = (idc.print_insn_mnem(ea) or "").lower().strip()
            category = match_insn(ea, mnem) if mnem else None
            if category:
                rows.append((ea, [mnem, category, disasm(ea), raw_bytes(ea), func_name(ea)]))
    except ScanCancelled:
        log("Scan cancelled, results are partial.")
    finally:
        ida_kernwin.hide_wait_box()
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
    log("Found %d match(es)." % len(rows))
    show_results(rows)


if __name__ == "__main__":
    main()
