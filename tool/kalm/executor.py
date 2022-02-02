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

_project_kwargs = {
    'auto_load_libs': False,
    'use_sim_procedures': False,
    'engine': KalmEngine,
    # Use the base SimOS, not any specific OS, we shouldn't depend on anything
    'simos': SimOS
}

def create_blank_state(thing, arch='amd64'):
    if isinstance(thing, str):
        proj = angr.Project(thing, **_project_kwargs)
    elif isinstance(thing, bytes):
        proj = angr.load_shellcode(thing, arch, **_project_kwargs)
    else:
        raise Exception("create_blank_state expects an str (path) or bytes (shellcode)")
    # TODO check out whether adding DOWNSIZE_Z3 helps mem use
    state = proj.factory.blank_state(
        # FAST_REGISTERS: see our __init__
        # SYMBOL_FILL_UNCONSTRAINED_*: it seems there's no way around enabling these, since code can access uninitialized variables (common in the "return bool, take in a pointer to the result" pattern)
        add_options={angr.sim_options.FAST_REGISTERS, angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
        # COPY_STATES: Don't copy states when executing, we'll copy what we need
        # TRACK_CONSTRAINT_ACTIONS: Not sure why angr does this by default, but we don't need to track constraints as history actions
        remove_options={angr.sim_options.COPY_STATES, angr.sim_options.TRACK_CONSTRAINT_ACTIONS}
    )
    state.solver._stored_solver = KalmSolver()
    # Force init of the path plugin so it can record everything
    ignored = state.path
    return state

def create_calling_state(state, function_thing, function_prototype, function_args, externals):
    # Discard previous history, otherwise it might interact with the new execution in weird ways
    state.register_plugin('history', SimStateHistory())
    # Re-create a project, since we may need different externals than last time
    if state.project.filename is None:
        # this is rather dubious, but what else can we do?
        stream = state.project.loader._main_binary_stream
        stream.seek(0)
        new_proj = angr.Project(stream, main_opts={'backend': 'blob', 'arch': state.project.arch, 'entry_point': 0, 'base_addr': 0}, **_project_kwargs)
    else:
        new_proj = angr.Project(state.project.filename, **_project_kwargs)
    state.project = new_proj
    # Add our externals
    for (sym, proc) in externals.items():
        if not isinstance(sym, str) or new_proj.loader.find_symbol(sym) is not None:
            new_proj.hook_symbol(sym, proc())
    # Create the state
    if isinstance(function_thing, str):
        function_addr = new_proj.loader.find_symbol(function_thing).rebased_addr
    else:
        function_addr = function_thing
    return new_proj.factory.call_state(function_addr, *function_args, prototype=function_prototype, base_state=state)

def run_state(state, ret_width=None, allow_trap=False):
    global trapped_states # see our custom engine
    trapped_states = []
    sm = state.project.factory.simulation_manager(state)
    expl_tech = MergingExplorationTechnique(ret_width=ret_width)
    sm.use_technique(expl_tech)
    sm.run()
    if len(sm.errored) > 0:
        print("Error, e.g. at", sm.errored[0].state.regs.rip)
        sm.errored[0].reraise()
    if len(trapped_states) > 0 and not allow_trap:
        raise Exception("There are trapped states! e.g. " + str(trapped_states[0].regs.rip))
    return (sm.deadended, expl_tech.graph_as_dot())
