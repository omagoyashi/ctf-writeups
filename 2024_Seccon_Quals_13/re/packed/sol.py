import angr
import claripy
import sys

p = angr.Project("a.out", auto_load_libs=False)

good_address = 0x44eeaa
bad_address = 0x44eeda

input_size = 0x31
symbolic_input = claripy.BVS('input', input_size*8)
initial_state = p.factory.entry_state(stdin=symbolic_input)
simulation = p.factory.simgr(initial_state)


simulation.explore(find=good_address, avoid=bad_address)

if simulation.found:
    solution_state = simulation.found[0]

    print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
    print("sorry, no dice")

