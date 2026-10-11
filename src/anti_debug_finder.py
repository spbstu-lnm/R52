"""PEB read finder for IDA Pro 9.3.

Finds:
  1) reads of the TEB.Peb pointer slot: FS:[0x30] / GS:[0x60];
  2) likely reads/accesses through registers derived from that pointer.

Also flags APIs that expose/query PEB-related state or are commonly used for anti-debugging. API hits are classified as direct, query, loader, or weak indicators; an API call alone is not proof of a raw PEB read.

The script does not modify the IDB. Results are printed to IDA's Output window.
"""

import re

import ida_bytes
import ida_funcs
import ida_gdl
import ida_lines
import idautils
import idc


# IDA's usual x86 text rendering: fs:30h, fs:[30h], gs:60h, gs:[60h], etc.
_SEGMENT_PEB_RE = re.compile(
    r"\b(fs|gs)\s*:\s*(?:(?:byte|word|dword|qword|tbyte|xmmword|ymmword|zmmword)\s+ptr\s*)?"
    r"\[?\s*(0x[0-9a-f]+|[0-9a-f]+h|\d+)\b",
    re.IGNORECASE,
)


# Canonicalize register aliases, so EAX/RAX count as the same register family.
_REG_FAMILY = {}

def _register_family(canonical, aliases):
    for alias in aliases:
        _REG_FAMILY[alias] = canonical


_register_family("rax", ["rax", "eax", "ax", "al", "ah"])
_register_family("rbx", ["rbx", "ebx", "bx", "bl", "bh"])
_register_family("rcx", ["rcx", "ecx", "cx", "cl", "ch"])
_register_family("rdx", ["rdx", "edx", "dx", "dl", "dh"])
_register_family("rsi", ["rsi", "esi", "si", "sil"])
_register_family("rdi", ["rdi", "edi", "di", "dil"])
_register_family("rbp", ["rbp", "ebp", "bp", "bpl"])
_register_family("rsp", ["rsp", "esp", "sp", "spl"])
for _n in range(8, 16):
    _register_family("r%d" % _n, ["r%d" % _n, "r%dd" % _n, "r%dw" % _n, "r%db" % _n])

_REG_TOKEN_RE = re.compile(
    r"\b(" + "|".join(sorted(_REG_FAMILY.keys(), key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)

# Instructions in which operand 0 is not written (or only flags/implicit state change).
_NO_DEST_WRITE = {
    "cmp", "test", "push", "call", "jmp", "ret", "retn", "retf", "iret", "iretd", "iretq",
    "nop", "pause", "int", "int1", "int3", "into", "syscall", "sysenter", "sysexit", "ud2",
    "bt", "prefetch", "prefetchnta", "prefetcht0", "prefetcht1", "prefetcht2",
}

# A call may overwrite caller-saved registers. These are cleared from the analysis state.
_CALL_CLOBBERED = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}

_COPY_MNEMONICS = {"mov", "movabs"}


RESULTS = {}  # ea -> list[(category, detail)]


def _parse_number(token):
    token = token.strip().lower()
    if token.startswith("0x"):
        return int(token, 16)
    if token.endswith("h"):
        return int(token[:-1], 16)
    # IDA normally prints offsets in hex (with an h suffix); bare numbers are decimal.
    return int(token, 10)


def _peb_segment_operand(operand):
    """Return ('fs'/'gs', offset) only for the standard PEB pointer slots."""
    match = _SEGMENT_PEB_RE.search(operand or "")
    if not match:
        return None
    segment = match.group(1).lower()
    try:
        offset = _parse_number(match.group(2))
    except ValueError:
        return None
    if (segment == "fs" and offset == 0x30) or (segment == "gs" and offset == 0x60):
        return segment, offset
    return None


def _get_operands(ea):
    operands = []
    for i in range(8):
        text = idc.print_operand(ea, i)
        if not text:
            break
        operands.append(text.strip())
    return operands


def _get_instruction(ea):
    mnemonic = (idc.print_insn_mnem(ea) or "").lower().strip()
    if not mnemonic:
        return None, []
    return mnemonic, _get_operands(ea)


def _reg_family(operand):
    text = (operand or "").strip().lower()
    if text in _REG_FAMILY:
        return _REG_FAMILY[text]
    return None


def _memory_registers(operand):
    """Return register families explicitly used inside [...] in an operand."""
    text = operand or ""
    left = text.find("[")
    right = text.rfind("]")
    if left < 0 or right <= left:
        return set()
    expression = text[left + 1:right]
    return {_REG_FAMILY[token.lower()] for token in _REG_TOKEN_RE.findall(expression)}


def _memory_access_mode(mnemonic, operand_index):
    """Classify explicit memory operands. None means operand 0 is write-only or LEA."""
    if mnemonic == "lea":
        return None
    if operand_index == 0:
        # These instructions write their first explicit memory operand without reading it.
        if mnemonic.startswith("mov") or mnemonic.startswith("set") or mnemonic == "pop":
            return None
        # Common read/modify/write instructions.
        if mnemonic in {
            "add", "adc", "sub", "sbb", "and", "or", "xor", "inc", "dec", "neg", "not",
            "shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr", "xchg", "xadd",
            "cmpxchg", "bts", "btr", "btc", "shld", "shrd",
        }:
            return "R/W"
    return "R"


def _is_code(ea):
    try:
        return ida_bytes.is_code(ida_bytes.get_full_flags(ea))
    except Exception:
        return bool(idc.print_insn_mnem(ea))


def _instruction_addresses(start_ea, end_ea):
    for ea in idautils.Heads(start_ea, end_ea):
        if _is_code(ea):
            yield ea


def _add_result(ea, category, detail):
    items = RESULTS.setdefault(ea, [])
    value = (category, detail)
    if value not in items:
        items.append(value)


def _scan_direct_peb_slots():
    """Search all code segments, including code not currently assigned to a function."""
    for seg_start in idautils.Segments():
        seg_end = idc.get_segm_end(seg_start)
        for ea in _instruction_addresses(seg_start, seg_end):
            mnemonic, operands = _get_instruction(ea)
            if not mnemonic:
                continue
            for index, operand in enumerate(operands):
                peb_slot = _peb_segment_operand(operand)
                if peb_slot is None:
                    continue
                mode = _memory_access_mode(mnemonic, index)
                if mode is None:
                    continue
                segment, offset = peb_slot
                if index > 0 and mnemonic in _COPY_MNEMONICS and _reg_family(operands[0]):
                    category = "PEB_PTR_LOAD"
                elif mode == "R/W":
                    category = "PEB_SLOT_RMW"
                else:
                    category = "PEB_SLOT_READ"
                _add_result(
                    ea,
                    category,
                    "operand %d=%s (%s:[0x%X], %s)" % (index, operand, segment.upper(), offset, mode),
                )


def _writes_operand0(mnemonic):
    if not mnemonic:
        return False
    if mnemonic in _NO_DEST_WRITE or mnemonic.startswith("j") or mnemonic.startswith("loop"):
        return False
    return True


def _transfer_block(instructions, initial_state):
    """Forward may-analysis: set of registers that may still point into/from the PEB."""
    state = set(initial_state)
    for ea in instructions:
        mnemonic, operands = _get_instruction(ea)
        if not mnemonic:
            continue

        if mnemonic == "call":
            state.difference_update(_CALL_CLOBBERED)
            continue

        if not operands:
            continue
        dest = _reg_family(operands[0])
        if not dest:
            continue

        direct_pointer_load = (
            mnemonic in _COPY_MNEMONICS
            and any(index > 0 and _peb_segment_operand(op) is not None for index, op in enumerate(operands))
        )
        copy_from_tracked_reg = (
            mnemonic in _COPY_MNEMONICS
            and len(operands) > 1
            and _reg_family(operands[1]) in state
        )
        lea_from_tracked_reg = (
            mnemonic == "lea"
            and any(_memory_registers(op) & state for op in operands[1:])
        )

        if direct_pointer_load or copy_from_tracked_reg or lea_from_tracked_reg:
            state.add(dest)
        elif mnemonic.startswith("cmov"):
            # Conditional move may keep the old destination or copy a tracked source.
            if len(operands) > 1 and _reg_family(operands[1]) in state:
                state.add(dest)
        elif _writes_operand0(mnemonic):
            state.discard(dest)

    return state


def _find_indirect_peb_accesses():
    """Track PEB-derived registers between basic blocks in each analyzed function."""
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        try:
            flow = ida_gdl.FlowChart(func)
            blocks = list(flow)
        except Exception as exc:
            print("[PEB-Finder] Cannot build CFG for %s: %s" % (hex(func_ea), exc))
            continue
        if not blocks:
            continue

        block_by_id = {block.id: block for block in blocks}
        instructions = {}
        predecessors = {}
        for block in blocks:
            instructions[block.id] = list(_instruction_addresses(block.start_ea, block.end_ea))
            try:
                predecessors[block.id] = [pred.id for pred in block.preds() if pred.id in block_by_id]
            except Exception:
                predecessors[block.id] = []

        in_states = {block.id: set() for block in blocks}
        out_states = {block.id: set() for block in blocks}

        # The lattice is finite (register families only), so this reaches a fixed point.
        changed = True
        while changed:
            changed = False
            for block in blocks:
                incoming = set()
                for pred_id in predecessors[block.id]:
                    incoming.update(out_states[pred_id])
                outgoing = _transfer_block(instructions[block.id], incoming)
                if incoming != in_states[block.id] or outgoing != out_states[block.id]:
                    in_states[block.id] = incoming
                    out_states[block.id] = outgoing
                    changed = True

        # Re-run each block with its final IN state and report memory reads through tracked regs.
        for block in blocks:
            state = set(in_states[block.id])
            for ea in instructions[block.id]:
                mnemonic, operands = _get_instruction(ea)
                if not mnemonic:
                    continue

                for index, operand in enumerate(operands):
                    mode = _memory_access_mode(mnemonic, index)
                    if mode is None:
                        continue
                    bases = _memory_registers(operand) & state
                    if not bases:
                        continue
                    category = "PEB_FIELD_READ" if mode == "R" else "PEB_FIELD_RMW"
                    _add_result(
                        ea,
                        category,
                        "operand %d=%s; PEB-derived register(s)=%s; mode=%s"
                        % (index, operand, ",".join(sorted(bases)), mode),
                    )

                # Keep the state transfer identical to the fixed-point pass.
                state = _transfer_block([ea], state)



# APIs are grouped by the kind of evidence their use provides.  An API hit is
# not the same as a raw PEB dereference; see each rule's explanation.
_API_RULES = {
    "IsDebuggerPresent": (
        "WINAPI_ANTI_DEBUG",
        "Checks whether the calling process is being debugged. Commonly associated with PEB.BeingDebugged, but the call alone does not prove that this module directly reads the PEB.",
    ),
    "CheckRemoteDebuggerPresent": (
        "WINAPI_ANTI_DEBUG",
        "Checks whether the specified process is being debugged; this is an anti-debugging indicator, not proof of a direct PEB read by the caller.",
    ),
    "NtQueryInformationProcess": (
        "WINAPI_PEB_QUERY",
        "Native process query. ProcessBasicInformation (class 0) returns a structure containing PebBaseAddress; ProcessDebugPort (class 7) is also used for anti-debugging. The information class is not inferred here.",
    ),
    "ZwQueryInformationProcess": (
        "WINAPI_PEB_QUERY",
        "Native process query. ProcessBasicInformation (class 0) returns a structure containing PebBaseAddress; ProcessDebugPort (class 7) is also used for anti-debugging. The information class is not inferred here.",
    ),
    "RtlGetCurrentPeb": (
        "WINAPI_PEB_ACCESS",
        "Returns the current process's PEB pointer when this ntdll export is available; strongest API-level PEB indicator in this list.",
    ),
    "RtlGetCurrentTeb": (
        "WINAPI_TEB_ACCESS",
        "Returns the current thread's TEB; the TEB contains a pointer to the PEB, but a PEB read is not proven by this call alone.",
    ),
    "NtCurrentTeb": (
        "WINAPI_TEB_ACCESS",
        "TEB accessor/intrinsic name. This can be a macro or compiler intrinsic rather than an imported function; inspect the surrounding code.",
    ),
    "NtSetInformationThread": (
        "WINAPI_ANTI_DEBUG",
        "Native thread-information API often associated with ThreadHideFromDebugger; the information class is not inferred here and the call alone does not prove a PEB read.",
    ),
    "ZwSetInformationThread": (
        "WINAPI_ANTI_DEBUG",
        "Native thread-information API often associated with ThreadHideFromDebugger; the information class is not inferred here and the call alone does not prove a PEB read.",
    ),
    "NtQuerySystemInformation": (
        "WINAPI_DEBUG_QUERY",
        "Native system-information query; can be used for kernel-debugger checks with certain information classes. The class is not inferred here.",
    ),
    "ZwQuerySystemInformation": (
        "WINAPI_DEBUG_QUERY",
        "Native system-information query; can be used for kernel-debugger checks with certain information classes. The class is not inferred here.",
    ),
    "RtlQueryProcessDebugInformation": (
        "WINAPI_DEBUG_QUERY",
        "RTL process/debug-information query; potentially debugger-related, but not itself proof of a direct PEB dereference.",
    ),
    "OutputDebugStringA": (
        "WINAPI_DEBUG_RELATED",
        "Sends a string to the debugger. It may participate in debugger-detection patterns, but is not a PEB read by itself.",
    ),
    "OutputDebugStringW": (
        "WINAPI_DEBUG_RELATED",
        "Sends a string to the debugger. It may participate in debugger-detection patterns, but is not a PEB read by itself.",
    ),
    "GetModuleHandleA": (
        "WINAPI_LOADER",
        "Module-loader API. The loader maintains module state associated with PEB.Ldr, but this call does not prove that the caller directly reads the PEB.",
    ),
    "GetModuleHandleW": (
        "WINAPI_LOADER",
        "Module-loader API. The loader maintains module state associated with PEB.Ldr, but this call does not prove that the caller directly reads the PEB.",
    ),
    "GetModuleHandleExA": (
        "WINAPI_LOADER",
        "Module-loader API. The loader maintains module state associated with PEB.Ldr, but this call does not prove that the caller directly reads the PEB.",
    ),
    "GetModuleHandleExW": (
        "WINAPI_LOADER",
        "Module-loader API. The loader maintains module state associated with PEB.Ldr, but this call does not prove that the caller directly reads the PEB.",
    ),
    "GetProcAddress": (
        "WINAPI_API_RESOLUTION",
        "Resolves an API by name/address. Can hide later API usage from import-based analysis; inspect nearby name strings and indirect calls.",
    ),
    "LdrGetProcedureAddress": (
        "WINAPI_API_RESOLUTION",
        "Native loader API resolver; may be used for dynamic API resolution, including anti-debug APIs.",
    ),
    "LdrGetDllHandle": (
        "WINAPI_LOADER",
        "Native loader/module lookup API; related to loader state, but not proof that the caller directly reads PEB.Ldr.",
    ),
    "LdrGetDllHandleEx": (
        "WINAPI_LOADER",
        "Native loader/module lookup API; related to loader state, but not proof that the caller directly reads PEB.Ldr.",
    ),
    "LdrEnumerateLoadedModules": (
        "WINAPI_LOADER",
        "Enumerates loaded modules through the native loader; related to loader state associated with PEB.Ldr.",
    ),
    "LdrLoadDll": (
        "WINAPI_LOADER",
        "Native loader API; related to loader state associated with PEB.Ldr, but the call itself is not a direct PEB read.",
    ),
    "LoadLibraryA": (
        "WINAPI_LOADER",
        "Module-loader API; indirect/low-confidence PEB indicator only.",
    ),
    "LoadLibraryW": (
        "WINAPI_LOADER",
        "Module-loader API; indirect/low-confidence PEB indicator only.",
    ),
    "LoadLibraryExA": (
        "WINAPI_LOADER",
        "Module-loader API; indirect/low-confidence PEB indicator only.",
    ),
    "LoadLibraryExW": (
        "WINAPI_LOADER",
        "Module-loader API; indirect/low-confidence PEB indicator only.",
    ),
    "GetCommandLineA": (
        "WINAPI_PROCESS_PARAMETERS",
        "Returns the process command line, whose backing process-parameter state is associated with the PEB. This is indirect evidence, not a raw PEB read.",
    ),
    "GetCommandLineW": (
        "WINAPI_PROCESS_PARAMETERS",
        "Returns the process command line, whose backing process-parameter state is associated with the PEB. This is indirect evidence, not a raw PEB read.",
    ),
}

_API_RULES_LOWER = {name.lower(): (name, info[0], info[1]) for name, info in _API_RULES.items()}
_API_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_@$?.!]*")


def _normalize_api_token(token):
    """Normalize IDA import/thunk spellings such as __imp_Foo, _Foo@8 and j_Foo."""
    value = (token or "").strip().split("!")[-1].lower()
    value = re.sub(r"@\d+$", "", value)
    for prefix in ("__imp_", "_imp_", "imp_", "j_", "__cdecl_", "__stdcall_"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    value = value.lstrip("_")
    # Some IDBs qualify imported symbols with a DLL-like prefix, e.g. KERNEL32_Foo.
    if value not in _API_RULES_LOWER:
        for api_lower in _API_RULES_LOWER:
            if value.endswith("_" + api_lower):
                value = api_lower
                break
    return value


def _api_matches_text(text):
    matches = {}
    for token in _API_TOKEN_RE.findall(text or ""):
        normalized = _normalize_api_token(token)
        rule = _API_RULES_LOWER.get(normalized)
        if rule:
            canonical, category, description = rule
            matches[canonical] = (category, description)
    return matches


def _scan_winapi_calls():
    """Find direct WinAPI/NTAPI calls by disassembly text and named xrefs."""
    # Text matching works for usual IDA spellings such as call cs:__imp_IsDebuggerPresent.
    for seg_start in idautils.Segments():
        seg_end = idc.get_segm_end(seg_start)
        for ea in _instruction_addresses(seg_start, seg_end):
            mnemonic = (idc.print_insn_mnem(ea) or "").lower().strip()
            if mnemonic not in ("call", "jmp"):
                continue
            disasm = _disassembly(ea)
            for api_name, (category, description) in _api_matches_text(disasm).items():
                _add_result(
                    ea,
                    category,
                    "API %s via %s" % (api_name, mnemonic.upper()),
                )

    # Xrefs cover cases where import/function names are present in the IDB but omitted
    # from the rendered instruction (for example calls through an import thunk).
    for name_ea, name in idautils.Names():
        api_matches = _api_matches_text(name)
        if not api_matches:
            continue
        for api_name, (category, description) in api_matches.items():
            try:
                refs = idautils.XrefsTo(name_ea, 0)
                for xref in refs:
                    site = xref.frm
                    if not _is_code(site):
                        continue
                    mnemonic = (idc.print_insn_mnem(site) or "").lower().strip()
                    if mnemonic not in ("call", "jmp"):
                        continue
                    _add_result(
                        site,
                        category,
                        "API %s referenced by named symbol %s"
                        % (api_name, name),
                    )
            except Exception:
                # Some name/xref combinations (e.g. malformed or partially loaded IDBs)
                # are not queryable; text-based scanning above still works.
                pass


def _scan_dynamic_api_name_strings():
    """Find referenced string literals naming APIs, useful for GetProcAddress cases.

    A matching string is only a candidate: the script cannot establish from the string
    alone that GetProcAddress/LdrGetProcedureAddress is actually invoked with it.
    """
    try:
        strings = idautils.Strings()
        strings.setup()
    except Exception:
        return

    for string_item in strings:
        try:
            string_ea = string_item.ea
            value = str(string_item).strip().strip("\x00")
        except Exception:
            continue
        matches = _api_matches_text(value)
        if not matches:
            continue
        # Only report exact API-name strings (not incidental prose containing a name).
        normalized_value = _normalize_api_token(value)
        exact = _API_RULES_LOWER.get(normalized_value)
        if not exact:
            continue
        api_name, category, description = exact
        try:
            refs = list(idautils.DataRefsTo(string_ea))
        except Exception:
            refs = []
        if not refs:
            continue
        for ref_ea in refs:
            if not _is_code(ref_ea):
                continue
            _add_result(
                ref_ea,
                "WINAPI_API_STRING",
                "Reference to string %r (candidate dynamic API name: %s); verify a nearby GetProcAddress/LdrGetProcedureAddress call."
                % (value, api_name),
            )

def _disassembly(ea):
    try:
        return ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "").strip()
    except Exception:
        return idc.GetDisasm(ea) or ""


def main():
    RESULTS.clear()
    print("\n" + "=" * 92)
    print("[PEB-Finder] IDA Pro 9.3 - scanning direct/derived PEB accesses and WinAPI/NTAPI usage")
    _scan_direct_peb_slots()
    _find_indirect_peb_accesses()
    _scan_winapi_calls()
    _scan_dynamic_api_name_strings()

    if not RESULTS:
        print("[PEB-Finder] No matching references found.")
        print("=" * 92)
        return

    print("[PEB-Finder] Unique instruction addresses: %d" % len(RESULTS))
    print("[PEB-Finder] Categories include direct PEB reads, WinAPI/NTAPI anti-debug and process queries, loader calls, and candidate dynamic API-name strings.")
    print("-" * 92)

    for ea in sorted(RESULTS):
        func_name = idc.get_func_name(ea) or "<no function>"
        categories = ", ".join(sorted({category for category, _ in RESULTS[ea]}))
        print("%s  %-30s  %-28s  %s" % ("0x%X" % ea, categories, func_name, _disassembly(ea)))
        for _, detail in RESULTS[ea]:
            print("    - " + detail)

    print("-" * 92)
    print("[PEB-Finder] Done. The database was not modified.")
    print("=" * 92 + "\n")


if __name__ == "__main__":
    main()
