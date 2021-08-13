import angr
from angr.sim_state import SimState
from angr.simos import SimOS
from angr.state_plugins import SimStateHistory
import claripy

import kalm
from kalm.engine import KalmEngine
from kalm.plugins import PathPlugin
from kalm.merging import MergingExplorationTechnique
from kalm.solver import KalmSolver


def _create_project(binary_path):
    # Use the base SimOS, not any specific OS, we shouldn't depend on anything
    return angr.Project(binary_path, auto_load_libs=False, use_sim_procedures=False, engine=KalmEngine, simos=SimOS)

# TODO make sure for all states we use the 'symbolic' option set, but try removing COW_STATES (copying states to execute them), it seems not useful to us
def create_blank_state(binary_path):
    proj = _create_project(binary_path)
    state = proj.factory.blank_state()
    # Don't copy states when executing, we'll copy what we need
    state.options.remove(angr.sim_options.COPY_STATES)
    # TODO: It seems there's no way around enabling these, since code can access uninitialized variables (common in the "return bool, take in a pointer to the result" pattern)
    state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    state.solver._stored_solver = KalmSolver()
    return state

def create_calling_state(state, function_thing, function_args, externals):
    # Discard previous history, otherwise it might interact with the new execution in weird ways
    state.register_plugin('history', SimStateHistory())
    # Re-create a project, since we may need different externals than last time
    new_proj = _create_project(state.project.filename)
    state.project = new_proj
    # Add our externals
    for (name, proc) in externals.items():
        if new_proj.loader.find_symbol(name) is not None:
            new_proj.hook_symbol(name, PathPlugin.wrap(proc()))
    # Create the state
    if isinstance(function_thing, str):
        function_addr = new_proj.loader.find_symbol(function_thing).rebased_addr
    else:
        function_addr = function_thing
    return new_proj.factory.call_state(function_addr, *function_args, base_state=state)

def run_state(state, allow_trap=False):
    global trapped_states # see our custom engine
    trapped_states = []
    sm = state.project.factory.simulation_manager(state)
    sm.use_technique(MergingExplorationTechnique())
    sm.run()
    if len(sm.errored) > 0:
        print("Error, e.g. at", sm.errored[0].state.regs.rip)
        sm.errored[0].reraise()
    # We do not ever expect unsat states; this could mean e.g. a precondition was not met
    if len(sm.unsat) > 0:
        raise Exception("There are unsat states! e.g. " + ", ".join([str(c) for c in sm.unsat[0].solver.constraints]))
    if len(trapped_states) > 0 and not allow_trap:
        raise Exception("There are trapped states! e.g. " + str(trapped_states[0].regs.rip))
    return sm.deadended