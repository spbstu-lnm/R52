# IMPORTANT (angr >= 10): claripy now ships bundled inside angr as a
# Rust-backed rewrite (angr.rustylib.claripy), aliased to `angr.claripy`.
# A separately pip-installed legacy `claripy` package (if still present
# in the venv) is a DIFFERENT, type-incompatible implementation -- ASTs
# built with it are not recognized by state.solver.add(), which is what
# produces a misleading "expression must be a boolean" ClaripyTypeError
# no matter which comparison helper you use. Always import claripy
# through angr on angr 10+:
import angr
from angr import claripy

# load the binary
project = angr.Project("crackme18-2.exe", auto_load_libs=False)

# --- addresses from IDA ---
CHECK_FUNC_ADDR = 0x140001000  # address of sub_140001000 (the check wrapper function)

# RETURN_ADDR must be the address of the instruction *right after*
# `call sub_140001000` inside DialogFunc. Grab this from IDA -- without
# it, control never flows back into the caller and FIND_ADDR/AVOID_ADDR
# (which live in DialogFunc) are unreachable.
RETURN_ADDR = 0x140001BC8  # <-- FILL THIS IN from IDA

FIND_ADDR  = 0x140001BE6  # address of MessageBoxA (success path) in DialogFunc
AVOID_ADDR = 0x140001DBF  # address of the failure branch / return

# lengths of symbolic variables
USERNAME_LEN = 32
KEY_LEN = 32

# create symbolic variables for Username and Key (32 bytes each)
username_chars = [claripy.BVS(f'user_{i}', 8) for i in range(USERNAME_LEN)]
key_chars = [claripy.BVS(f'key_{i}', 8) for i in range(KEY_LEN)]

username_ast = claripy.Concat(*username_chars)
key_ast = claripy.Concat(*key_chars)

# create a proper call state: this sets up the stack, the calling
# convention registers, AND a fake return address we control, so that
# when sub_140001000 returns, execution actually continues at
# RETURN_ADDR inside DialogFunc instead of jumping to garbage.
state = project.factory.call_state(
    CHECK_FUNC_ADDR,
    0, 0,            # placeholder args, overwritten below via rcx/rdx
    ret_addr=RETURN_ADDR,
)

# limit the symbols to printable ASCII characters.
# The ClaripyTypeError here is NOT about signed vs. unsigned comparison
# operators -- it happens the same way whether you use plain Python
# operators or claripy.UGE/ULE. The real cause is that `c` is an 8-bit
# BVS while the raw Python ints 0x20/0x7e aren't reliably coerced to a
# matching 8-bit bitvector. Wrapping them explicitly as same-width BVV
# fixes it regardless of which comparison helper is used on top.
PRINTABLE_LOW = claripy.BVV(0x20, 8)
PRINTABLE_HIGH = claripy.BVV(0x7e, 8)

for c in username_chars:
    state.solver.add(claripy.UGE(c, PRINTABLE_LOW))
    state.solver.add(claripy.ULE(c, PRINTABLE_HIGH))
for c in key_chars:
    state.solver.add(claripy.UGE(c, PRINTABLE_LOW))
    state.solver.add(claripy.ULE(c, PRINTABLE_HIGH))

# imitate args of sub_140001000(__int64 username, __int64 key)
# x64 Windows -> args are passed via RCX and RDX
# allocate memory for strings on angr heap.
# Note: the default heap plugin is SimHeapBrk, a minimal brk()-style
# heap that only exposes the low-level allocate()/release() primitives
# -- it has no public malloc() method (that only exists on richer
# plugins like SimHeapPTMalloc/SimHeapLibc). Since we just need raw
# scratch buffers here, allocate() is the right call.
username_ptr = state.heap.allocate(USERNAME_LEN)
key_ptr = state.heap.allocate(KEY_LEN)

state.memory.store(username_ptr, username_ast)
state.memory.store(key_ptr, key_ast)

state.regs.rcx = username_ptr
state.regs.rdx = key_ptr

# run simulation
simulation = project.factory.simgr(state)

# drop unconstrained states as we go so a bad jump doesn't silently
# blow up exploration time/memory
simulation.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

# check if a solution was found
if simulation.found:
    solution_state = simulation.found[0]

    # extract the concrete values of the symbolic variables
    username_res = solution_state.solver.eval(username_ast, cast_to=bytes)
    key_res = solution_state.solver.eval(key_ast, cast_to=bytes)

    # trim the null bytes and decode to string
    print(f"[+] Success!")
    print(f"[+] Username: {username_res.split(b'\x00')[0].decode('utf-8', errors='ignore')}")
    print(f"[+] Serial Key: {key_res.split(b'\x00')[0].decode('utf-8', errors='ignore')}")
else:
    print("[-] No solution found.")
