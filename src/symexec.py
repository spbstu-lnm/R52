import angr
import claripy

# load the binary
project = angr.Project("crackme18-2.exe", auto_load_libs=False)

# addresses from IDA
START_ADDR = 0x140001000  # address of the check wrapper function
FIND_ADDR  = 0x140001BE6  # address of MessageBoxA in DialogFunc
AVOID_ADDR = 0x140001DBF  # address of the failure branch / return

# lengths of symbolic variables
USERNAME_LEN = 32
KEY_LEN = 32

# create symbolic variables for Username and Key (32 bytes each)
username_chars = [claripy.BVS(f'user_{i}', 8) for i in range(USERNAME_LEN)]
key_chars = [claripy.BVS(f'key_{i}', 8) for i in range(KEY_LEN)]

username_ast = claripy.Concat(*username_chars)
key_ast = claripy.Concat(*key_chars)

# create the initial state at the entry point of the check function
# TODO: change to call_state??
state = project.factory.blank_state(addr=START_ADDR)

# limit the symbols to printable ASCII characters
# (should speed up the solving process)
for c in username_chars:
    # TODO: fix ClaripyTypeError
    state.solver.add(claripy.UGE(c, 0x20))
    state.solver.add(c <= 0x7e)
for c in key_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

# imitate args of sub_140001000(__int64 username, __int64 key)
# x64 Windows -> args are passed via RCX and RDX
# allocate memory for strings on angr heap
username_ptr = state.heap.malloc(USERNAME_LEN)
key_ptr = state.heap.malloc(KEY_LEN)

state.memory.store(username_ptr, username_ast)
state.memory.store(key_ptr, key_ast)

state.regs.rcx = username_ptr
state.regs.rdx = key_ptr

# run simulation
simulation = project.factory.simgr(state)
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
