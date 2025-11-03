import angr
import sys

project = angr.Project('simple', auto_load_libs=False)
initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state)

def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Access Granted' in stdout_output

def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Access Denied' in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
    solution_state = simulation.found[0]
    print("Soluzione trovata:")
    found_password = solution_state.posix.dumps(sys.stdin.fileno())
    print(f"Password trovata: {found_password}")
else:
    raise Exception('Impossibile trovare la password')


#esamina la password