import angr
from angr.sim_state import SimState
from executors.binary.plugin_dummy import DummyPlugin
from executors.binary.ghost_maps import GhostMaps
from executors.binary.memory_split import SplitMemory
from executors.binary.metadata import Metadata
from executors.binary.path import Path
import random

# Disable logs we don't care about
import logging
logging.getLogger('cle.loader').setLevel('ERROR')
logging.getLogger('angr.engines.successors').setLevel('ERROR')
logging.getLogger('angr.project').setLevel('ERROR')
#logging.getLogger('angr').setLevel('DEBUG')

# Instantiate this and call install() on it to make angr's externals management sound (i.e., any external call will error, not silently be symbolic)
class EmptyLibrary():
  class Abort(angr.SimProcedure):
    NO_RET = True
    def run(self, x):
      raise ('Unimplemented function: ' + self.display_name)

  def __init__(self):
    # the existence of syscall_number_mapping and minimum/maximum_syscall_number is required by angr
    self.syscall_number_mapping = ['i386', 'amd64']

  def install(self):
    # remove everything else
    angr.SIM_LIBRARIES.clear()
    angr.SIM_PROCEDURES.clear()
    # set ourselves as a library
    angr.SIM_LIBRARIES['externals'] = self
    # angr expects a library to be named linux
    angr.SIM_LIBRARIES['linux'] = self
    # angr hardcodes some linux procedures
    angr.SIM_PROCEDURES['linux_loader'] = {
      'LinuxLoader': EmptyLibrary.Abort,
      '_dl_rtld_lock_recursive': EmptyLibrary.Abort,
      '_dl_rtld_unlock_recursive': EmptyLibrary.Abort,
      '_dl_initial_error_catch_tsd': EmptyLibrary.Abort
    }
    angr.SIM_PROCEDURES['linux_kernel'] = {
      '_vsyscall': EmptyLibrary.Abort
    }
    # angr hardcodes some stubs
    angr.SIM_PROCEDURES['stubs'] = {
      'ReturnUnconstrained': EmptyLibrary.Abort,
      'CallReturn': angr.procedures.stubs.CallReturn.CallReturn, # to make call_state work
      'UnresolvableCallTarget': EmptyLibrary.Abort,
      'UnresolvableJumpTarget': EmptyLibrary.Abort,
      'PathTerminator': angr.procedures.stubs.PathTerminator.PathTerminator # this is a real one
    }

  # immutable; this makes things simpler
  def copy(self): return self

  # no syscalls available
  def minimum_syscall_number(self, abi): return 0
  def maximum_syscall_number(self, abi): return 0



# Keep only what we need in the engine
# Not sure SimEngineFailure is even needed, but just in case...
from angr.engines.failure import SimEngineFailure
from angr.engines.hook import HooksMixin
from angr.engines.vex import HeavyVEXMixin
class CustomEngine(SimEngineFailure, HooksMixin, HeavyVEXMixin):
    pass


bin_exec_initialized = False

def create_sim_manager(binary, ext_funcs, main_func_name, *main_func_args, base_state=None):
  global bin_exec_initialized
  if not bin_exec_initialized:
    EmptyLibrary().install()
    random.seed(10) # not sure if this is useful, but just in case...
    bin_exec_initialized = True

  # No explicit globals (we use metadata instead)
  SimState.register_default("globals", DummyPlugin)
  # No explicit heap (we use our memory's "allocate" instead)
  SimState.register_default("heap", DummyPlugin)
  # Our plugins
  SimState.register_default("metadata", Metadata)
  SimState.register_default("sym_memory", SplitMemory) # SimState translates "sym_memory" to "memory" under standard options
  SimState.register_default("maps", GhostMaps)
  SimState.register_default("path", Path)

  proj = angr.Project(binary, auto_load_libs=False, use_sim_procedures=False, engine=CustomEngine)
  for (fname, fproc) in ext_funcs.items():
    if proj.loader.find_symbol(fname) is not None:
      proj.hook_symbol(fname, Path.wrap(fproc()))
  main_func = proj.loader.find_symbol(main_func_name)
  # Not sure if this is needed but let's do it just in case, to make sure we don't change the base state
  base_state = base_state.copy() if base_state is not None else None
  init_state = proj.factory.call_state(main_func.rebased_addr, *main_func_args, base_state=base_state, add_options={angr.sim_options.TRACK_SOLVER_VARIABLES})
  # It seems there's no way around enabling these, since code can access uninitialized variables (common in the "return bool, take in a pointer to the result" pattern)
  init_state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
  init_state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
  sm = proj.factory.simulation_manager(init_state)
  # We want exhaustive symbex, DFS makes debugging a lot easier by not interleaving paths
  sm.use_technique(angr.exploration_techniques.DFS())
  return sm
