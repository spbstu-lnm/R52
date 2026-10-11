"""
IDA Pro 9.3 / IDAPython: find potential timing measurement sites.

Searches for:
  * RDTSC instructions (and RDTSCP optionally);
  * references to imported/named GetTickCount and GetTickCount64 APIs;
  * direct API calls and calls through simple import-thunk functions;
  * nearby pairs of RDTSC/API calls within the same function.

Run via File -> Script file... and select this .py file.
The database is not modified by default. Comments can be enabled in the settings below.
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


# ----------------------------- Settings -------------------------------------

SEARCH_RDTSCP = True
ANNOTATE_COMMENTS = False
# Maximum byte distance between two candidates for them to be reported as a
# possible measurement pair. This is a heuristic, not proof of a relationship.
MAX_PAIR_DISTANCE = 0x1000

# Also match decorated names such as __imp_GetTickCount and _GetTickCount@0.
API_NAME_RE = re.compile(r"gettickcount(?:64)?(?:@\d+)?$", re.IGNORECASE)
CALL_MNEMONICS = {"call", "callq", "bl", "blx", "blr", "jal", "jalr", "lcall"}
JUMP_MNEMONICS = {"jmp", "jmpq", "b", "br", "bx"}
COMMENT_MARKER = "[TimingFinder]"


def log(message=""):
    """Write a message to IDA's Output window."""
    ida_kernwin.msg(str(message) + "\n")


def is_timing_api_name(name):
    if not name:
        return False
    return API_NAME_RE.search(str(name)) is not None


def is_code(ea):
    if ea is None or ea == idc.BADADDR:
        return False
    try:
        return ida_bytes.is_code(ida_bytes.get_full_flags(ea))
    except Exception:
        return False


def mnemonic(ea):
    return (idc.print_insn_mnem(ea) or "").lower()


def disasm(ea):
    try:
        line = idc.generate_disasm_line(ea, 0)
        if line:
            return ida_lines.tag_remove(line)
    except Exception:
        pass
    return mnemonic(ea)


def get_function_info(ea):
    """Return (start_ea, display_name), or (None, '<outside function>')."""
    func = ida_funcs.get_func(ea)
    if not func:
        return None, "<outside function>"

    start = func.start_ea
    name = idc.get_name(start) or ("sub_%X" % start)
    return start, "%s @ 0x%X" % (name, start)


def add_comment(ea, text):
    """Add a comment without duplicating this script's own marker."""
    if not ANNOTATE_COMMENTS:
        return
    old = idc.get_cmt(ea, False) or ""
    if COMMENT_MARKER in old and text in old:
        return
    new_text = (old + " | " if old else "") + COMMENT_MARKER + " " + text
    idc.set_cmt(ea, new_text, False)


def collect_timing_api_targets():
    """Collect import addresses and names resembling the GetTickCount API."""
    targets = {}  # ea -> set(label)

    def add_target(ea, label):
        if ea is None or ea == idc.BADADDR:
            return
        targets.setdefault(ea, set()).add(str(label))

    # First, collect names, including names assigned to IDA thunk functions.
    for ea, name in idautils.Names():
        if is_timing_api_name(name):
            add_target(ea, name)

    # Next, scan the import table: not all imported functions are necessarily
    # represented in Names() in the same way.
    try:
        module_count = ida_nalt.get_import_module_qty()
    except Exception as exc:
        log("[!] Failed to retrieve the import list: %s" % exc)
        module_count = 0

    for module_index in range(module_count):
        module_name = ida_nalt.get_import_module_name(module_index) or "<unknown DLL>"

        def import_callback(ea, name, ordinal, dll=module_name):
            if is_timing_api_name(name):
                label = "%s!%s" % (dll, name)
                add_target(ea, label)
            return True  # Continue enumerating imports.

        try:
            ida_nalt.enum_import_names(module_index, import_callback)
        except Exception as exc:
            log("[!] Error reading imports from %s: %s" % (module_name, exc))

    return targets


def scan_rdtsc():
    """Scan instructions in executable segments."""
    wanted = {"rdtsc"}
    if SEARCH_RDTSCP:
        wanted.add("rdtscp")

    found = []
    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(seg_start)
        if not seg:
            continue
        if not (seg.perm & ida_segment.SEGPERM_EXEC):
            continue

        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
            if not is_code(ea):
                continue
            mnem = mnemonic(ea)
            if mnem in wanted:
                func_start, func_name = get_function_info(ea)
                found.append({
                    "ea": ea,
                    "mnem": mnem.upper(),
                    "func_start": func_start,
                    "func_name": func_name,
                    "disasm": disasm(ea),
                })
                add_comment(ea, "%s: possible cycle-counter measurement" % mnem.upper())

    return sorted(found, key=lambda item: item["ea"])


def is_call_mnemonic(mnem):
    return mnem in CALL_MNEMONICS or mnem.startswith("call")


def is_jump_mnemonic(mnem):
    return mnem in JUMP_MNEMONICS or mnem.startswith("jmp")


def scan_api_references(targets):
    """Return (calls, other references, discovered import-thunk functions)."""
    calls = {}       # source EA -> set(API labels)
    references = {}  # source EA -> set(API labels)
    possible_thunks = {}  # thunk start EA -> set(API labels)

    def add_event(table, ea, label):
        table.setdefault(ea, set()).add(label)

    for target_ea, labels in targets.items():
        for xref in idautils.XrefsTo(target_ea, 0):
            src = xref.frm
            if not is_code(src):
                continue

            mnem = mnemonic(src)
            func = ida_funcs.get_func(src)
            for label in labels:
                if is_call_mnemonic(mnem):
                    add_event(calls, src, label)
                    add_comment(src, "call to %s" % label)
                else:
                    add_event(references, src, label)
                    add_comment(src, "reference to %s" % label)

                # A simple import thunk usually starts with a JMP to the IAT/API.
                # Only check a JMP at the beginning of an IDA function, so an
                # arbitrary jump inside a regular function is not treated as a thunk.
                if (func and func.start_ea == src and is_jump_mnemonic(mnem)):
                    possible_thunks.setdefault(func.start_ea, set()).add(label)

    # If a JMP thunk was found, look one level up for CALL instructions to it.
    for thunk_ea, labels in possible_thunks.items():
        thunk_name = idc.get_name(thunk_ea) or ("thunk_%X" % thunk_ea)
        for xref in idautils.XrefsTo(thunk_ea, 0):
            src = xref.frm
            if not is_code(src) or not is_call_mnemonic(mnemonic(src)):
                continue
            for label in labels:
                add_event(calls, src, "%s via %s" % (label, thunk_name))
                add_comment(src, "call to %s via thunk %s" % (label, thunk_name))

    return calls, references, possible_thunks


def find_nearby_pairs(addresses):
    """Find adjacent addresses in the same function within the configured window."""
    by_function = {}
    for ea in sorted(addresses):
        func_start, _ = get_function_info(ea)
        if func_start is not None:
            by_function.setdefault(func_start, []).append(ea)

    pairs = []
    for func_start, eas in by_function.items():
        eas.sort()
        for left, right in zip(eas, eas[1:]):
            distance = right - left
            if distance <= MAX_PAIR_DISTANCE:
                pairs.append((left, right, func_start, distance))

    return sorted(pairs, key=lambda item: (item[2], item[0], item[1]))


def print_sites(title, events, labels_for_address=None):
    log("\n%s (%d):" % (title, len(events)))
    if not events:
        log("  none found")
        return

    for item in events:
        ea = item["ea"] if isinstance(item, dict) else item
        func_start, func_name = get_function_info(ea)
        label_text = ""
        if labels_for_address is not None:
            label_text = " | " + ", ".join(sorted(labels_for_address.get(ea, set())))
        log("  0x%X  [%s]%s" % (ea, func_name, label_text))
        if isinstance(item, dict) and item.get("disasm"):
            log("      %s" % item["disasm"])
        elif is_code(ea):
            log("      %s" % disasm(ea))


def print_pairs(title, pairs):
    log("\n%s (%d):" % (title, len(pairs)))
    if not pairs:
        log("  none found")
        return
    for left, right, func_start, distance in pairs:
        func_name = idc.get_name(func_start) or ("sub_%X" % func_start)
        log("  0x%X -> 0x%X  (%s, distance 0x%X bytes)" %
            (left, right, func_name, distance))


def main():
    log("=" * 72)
    log("TimingFinder for IDA Pro 9.3")
    log("Searching for RDTSC/RDTSCP and GetTickCount/GetTickCount64")
    log("Heuristic pair distance threshold: 0x%X bytes" % MAX_PAIR_DISTANCE)
    log("Database comments: %s" % ("enabled" if ANNOTATE_COMMENTS else "disabled"))

    rdtsc_sites = scan_rdtsc()
    api_targets = collect_timing_api_targets()
    api_calls, api_references, thunks = scan_api_references(api_targets)

    print_sites("RDTSC/RDTSCP instructions", rdtsc_sites)
    print_sites("GetTickCount/GetTickCount64 calls", sorted(api_calls), api_calls)
    print_sites("Other code references to the API (not necessarily calls)",
                sorted(api_references), api_references)

    rdtsc_pairs = find_nearby_pairs([item["ea"] for item in rdtsc_sites])
    api_pairs = find_nearby_pairs(sorted(api_calls))
    print_pairs("Possible RDTSC/RDTSCP pairs in the same function", rdtsc_pairs)
    print_pairs("Possible GetTickCount* call pairs in the same function", api_pairs)

    log("\nSummary: RDTSC/RDTSCP=%d, API targets=%d, API calls=%d, API refs=%d, thunk candidates=%d" %
        (len(rdtsc_sites), len(api_targets), len(api_calls), len(api_references), len(thunks)))
    log("Note: address proximity is only a heuristic; verify control flow and how the result is used.")
    log("=" * 72)


if __name__ == "__main__":
    main()
