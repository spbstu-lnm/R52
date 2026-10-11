# Rare instruction finder for IDA Pro 9.3 / IDAPython.

import re

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_lines
import ida_segment
import idautils
import idc


# Mnemonics to report. Extend or remove entries as needed.
RARE_MNEMONICS = {
    "cpuid": "CPU identification",
    "rdtsc": "Timing / anti-debug",
    "rdtscp": "Timing / anti-debug",
    "rdpmc": "Performance counter",
    "icebp": "Trap / anti-debug",
    "int1": "Trap / anti-debug",
    "int3": "Breakpoint",
    "ud2": "Invalid-opcode trap",
    "syscall": "System call",
    "sysret": "System call",
    "sysenter": "System call",
    "sysexit": "System call",
    "vmcall": "Virtualization",
    "vmmcall": "Virtualization",
    "vmrun": "Virtualization",
    "vmmcall": "Virtualization",
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
    "lar": "Protection check",
    "lsl": "Protection check",
    "verr": "Protection check",
    "verw": "Protection check",
    "swapgs": "System state",
    "rsm": "System state",
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

# IDA allows up to UA_MAXOP operands. Eight is a conservative fixed bound.
MAX_OPERANDS = 8

# Keep the chooser alive while its window is open.
_rare_insn_chooser = None


def _get_raw_bytes(ea, size):
    if size <= 0:
        return b""
    data = ida_bytes.get_bytes(ea, size)
    if data is None:
        return b""
    if isinstance(data, str):
        return data.encode("latin1", errors="ignore")
    return bytes(data)


def _get_operands(ea):
    operands = []
    for idx in range(MAX_OPERANDS):
        op_type = idc.get_operand_type(ea, idx)
        if op_type == idc.o_void:
            break
        text = idc.print_operand(ea, idx) or ""
        operands.append((idx, op_type, text.strip()))
    return operands


def _match_instruction(ea, mnemonic, raw, operands):
    """Return a category string if the instruction matches, otherwise None."""
    mnem = mnemonic.lower().strip()

    # INT 2Dh is used by some Windows anti-debugging checks.
    if mnem == "int":
        try:
            if (idc.get_operand_type(ea, 0) == idc.o_imm and
                    idc.get_operand_value(ea, 0) == 0x2D):
                return "INT 2D / anti-debug"
        except Exception:
            pass

    # ICEBP is encoded as F1. Some processor modules call it INT1.
    if mnem in ("icebp", "int1") or raw[:1] == b"\xF1":
        return "ICEBP / INT1 / anti-debug"

    if mnem in RARE_MNEMONICS:
        return RARE_MNEMONICS[mnem]

    # Report explicit SS register use, plus explicit SS segment overrides.
    for idx, op_type, op_text in operands:
        normalized = op_text.lower().replace(" ", "")
        if op_type == idc.o_reg and normalized == "ss":
            return "SS register use"
        if (op_type in (idc.o_mem, idc.o_phrase, idc.o_displ) and
                "ss:" in normalized):
            return "SS segment override"

    # LSS loads the stack segment implicitly.
    if mnem == "lss":
        return "Stack segment load (LSS)"

    # Access to control, debug, or test registers is often worth inspecting.
    for idx, op_type, op_text in operands:
        if op_type != idc.o_reg:
            continue
        reg = op_text.lower().strip()
        if re.match(r"^(cr|dr|tr)\d+$", reg):
            return "Control / debug / test register"

    return None


def _get_disassembly(ea):
    line = idc.generate_disasm_line(ea, 0)
    if line:
        return ida_lines.tag_remove(line).strip()
    return (idc.GetDisasm(ea) or "").strip()


def scan_database():
    """Scan IDA-recognized instruction heads in all segments."""
    results = []
    seen = set()

    ida_kernwin.show_wait_box("Scanning for rare instructions...")
    try:
        for seg_start in idautils.Segments():
            seg = ida_segment.getseg(seg_start)
            if seg is None:
                continue

            for ea in idautils.Heads(seg.start_ea, seg.end_ea):
                if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
                    continue

                mnemonic = (idc.print_insn_mnem(ea) or "").strip().lower()
                if not mnemonic:
                    continue

                size = idc.get_item_size(ea)
                raw = _get_raw_bytes(ea, size)
                operands = _get_operands(ea)
                category = _match_instruction(ea, mnemonic, raw, operands)
                if category is None:
                    continue

                key = (ea, category)
                if key in seen:
                    continue
                seen.add(key)

                func = ida_funcs.get_func_name(ea) or "<no function>"
                results.append({
                    "ea": ea,
                    "address": "0x%X" % ea,
                    "mnemonic": mnemonic,
                    "category": category,
                    "disassembly": _get_disassembly(ea),
                    "bytes": raw.hex(" ").upper(),
                    "function": func,
                })
    finally:
        ida_kernwin.hide_wait_box()

    results.sort(key=lambda item: item["ea"])
    return results


class RareInsnChooser(ida_kernwin.Choose):
    def __init__(self, results):
        self.results = results
        columns = [
            ["Address", 16],
            ["Mnemonic", 12],
            ["Category", 30],
            ["Disassembly", 48],
            ["Bytes", 22],
            ["Function", 28],
        ]
        super().__init__("Rare Instruction Finder", columns)

    def OnGetSize(self):
        return len(self.results)

    def OnGetLine(self, n):
        item = self.results[n]
        return [
            item["address"],
            item["mnemonic"],
            item["category"],
            item["disassembly"],
            item["bytes"],
            item["function"],
        ]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.results[n]["ea"])
        return (ida_kernwin.Choose.NOTHING_CHANGED, n)


def main():
    global _rare_insn_chooser

    results = scan_database()
    ida_kernwin.msg("[RareInsnFinder] Found %d match(es).\n" % len(results))

    if not results:
        ida_kernwin.info("No matching instructions found.")
        return

    _rare_insn_chooser = RareInsnChooser(results)
    if hasattr(_rare_insn_chooser, "Show"):
        _rare_insn_chooser.Show()
    else:
        _rare_insn_chooser.show()


if __name__ == "__main__":
    main()
