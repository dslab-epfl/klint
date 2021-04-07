import faulthandler
import random
import angr
from angr.sim_state import SimState
from angr.simos import SimOS
import claripy

from . import clock
from .ghost_maps import GhostMapsPlugin
from .maps_memory import MapsMemoryMixin
from .metadata import MetadataPlugin
from .objs_memory import ObjectsMemoryMixin
from .path import PathPlugin
from .pci import PciPlugin
from .plugin_dummy import DummyPlugin

# Disable logs we don't care about
import logging
logging.getLogger('cle.loader').setLevel('ERROR')
logging.getLogger('cle.backends.externs').setLevel('ERROR')
logging.getLogger('angr.engines.successors').setLevel('ERROR')
logging.getLogger('angr.project').setLevel('ERROR')
#logging.getLogger('angr').setLevel('DEBUG')

# Instantiate this and call install() on it to make angr's externals management sound (i.e., any external call will error, not silently be symbolic)
class EmptyLibrary():
    class Abort(angr.SimProcedure):
        NO_RET = True
        def run(self):
            raise Exception('Unimplemented function')

    def install(self):
        # remove everything else
        angr.SIM_LIBRARIES.clear()
        angr.SIM_PROCEDURES.clear()
        # set ourselves as a library
        angr.SIM_LIBRARIES['externals'] = self
        # angr hardcodes some stubs
        angr.SIM_PROCEDURES['stubs'] = {
            'ReturnUnconstrained': EmptyLibrary.Abort,
            'CallReturn': angr.procedures.stubs.CallReturn.CallReturn, # to make call_state work
            'UnresolvableCallTarget': EmptyLibrary.Abort,
            'UnresolvableJumpTarget': EmptyLibrary.Abort,
            'PathTerminator': angr.procedures.stubs.PathTerminator.PathTerminator # this is a real one
        }

    def get(self, name, arch):
        return EmptyLibrary.Abort

    # immutable; this makes things simpler
    def copy(self): return self


# Keep only what we need in the engine, and handle hlt, in, and out
from angr.engines.failure import SimEngineFailure
from angr.engines.hook import HooksMixin
from angr.engines.vex import HeavyVEXMixin
class CustomEngine(SimEngineFailure, HooksMixin, HeavyVEXMixin):
    def _perform_vex_stmt_Dirty_call(self, func_name, ty, args, func=None):
        if func_name == "amd64g_dirtyhelper_IN":# args = [portno (16b), size]
            if args[0].op != 'BVV':
                raise angr.errors.UnsupportedDirtyError("Symbolic port for 'in'")
            port = args[0].args[0]
            if args[1].op != 'BVV':
                raise angr.errors.UnsupportedDirtyError("Symbolic size for 'in'")
            size = args[1].args[0]
            return self.state.pci.handle_in(port, size)
        if func_name == "amd64g_dirtyhelper_OUT": # args = [portno (16b), data (32b), size]
            if args[0].op != 'BVV':
                raise angr.errors.UnsupportedDirtyError("Symbolic port for 'out'")
            port = args[0].args[0]
            if args[2].op != 'BVV':
                raise angr.errors.UnsupportedDirtyError("Symbolic size for 'out'")
            size = args[2].args[0]
            data = args[1][size*8-1:0]
            self.state.pci.handle_out(port, data, size)
            return None

        if func_name == 'amd64g_dirtyhelper_RDTSC': # no args
            return (clock.get_current_time(self.state) * clock.frequency_num) // clock.frequency_denom

        raise angr.errors.UnsupportedDirtyError("Unexpected angr 'dirty' call")

# Handle RDMSR, specifically register 0xCE which contains the clock frequency
from pyvex.lifting import register as pyvex_register
from pyvex.lifting.util import Type
from pyvex.lifting.util.instr_helper import Instruction
from pyvex.lifting.util.lifter_helper import GymratLifter
class Instruction_RDMSR(Instruction):
    name = "RDMSR"
    bin_format = "0000111100110010" # 0x0F32
    def compute_result(self):
        def amd64g_rdmsr(state, msr):
            # For now we only emulate the clock frequency
            if not msr.structurally_match(claripy.BVV(0xCE, 32)):
                raise Exception("Unknown R for RDMSR")
            high = claripy.BVS("msr_high", 32)
            low = claripy.BVS("msr_low", 32)
            low = low[31:16].concat(clock.frequency_num[7:0]).concat(low[7:0])
            state.regs.edx = high
            state.regs.eax = low
            return 0

        return self.ccall(Type.int_32, amd64g_rdmsr, [self.get("ecx", Type.int_32)])

class AMD64Spotter(GymratLifter):
    instrs = [Instruction_RDMSR]
pyvex_register(AMD64Spotter, 'AMD64')

# Keep only what we need in the solver
# We especially don't want ConstraintExpansionMixin, which adds constraints after an eval
# e.g. eval_upto(x, 2) -> [1, 2] results in added constraints x != 1 and x != 2
import claripy.frontend_mixins as cfms
from claripy.frontends import CompositeFrontend
from claripy import backends, SolverCompositeChild
class CustomSolver(
    cfms.ConstraintFixerMixin, # fixes types (e.g. bool to BoolV)
    cfms.ConcreteHandlerMixin, # short-circuit on concrete vals
    cfms.EagerResolutionMixin, # for eager backends
    cfms.ConstraintFilterMixin, # applies constraint filters (do we ever use that?)
    cfms.ConstraintDeduplicatorMixin, # avoids duplicate constraints
    cfms.SatCacheMixin, # caches satisfiable()
    cfms.SimplifySkipperMixin, # caches the "simplified" state
    cfms.SimplifyHelperMixin, # simplifies before calling the solver
    cfms.CompositedCacheMixin, # sounds useful
    CompositeFrontend # the actual frontend
):
    def __init__(self, template_solver=None, track=False, template_solver_string=None, **kwargs):
        template_solver = template_solver or SolverCompositeChild(track=track)
        template_solver_string = template_solver_string or SolverCompositeChild(track=track, backend=backends.z3)
        super().__init__(template_solver, template_solver_string, track=track, **kwargs)

# Keep only what we need in the memory, including our custom layers
import angr.storage.memory_mixins as csms
class CustomMemory(
    csms.NameResolutionMixin, # To allow uses of register names, which angr does internally when this is used for regs
    csms.DataNormalizationMixin, # To always get ASTs values
    csms.SizeNormalizationMixin, # To always get actual sizes in stores (required by some angr mixins)
    ObjectsMemoryMixin, # For modelled devices
    MapsMemoryMixin, # For the heap
    # --- Rest is inspired by DefaultMemory, minus stuff we definitely don't need; TODO: can we make this all read-only after init?
    csms.StackAllocationMixin,
    csms.ClemoryBackerMixin,
    csms.DictBackerMixin,
    csms.UltraPagesMixin,
    csms.DefaultFillerMixin,
    csms.PagedMemoryMixin
):
    pass


bin_exec_initialized = False

def create_sim_manager(binary, ext_funcs, main_func_name, *main_func_args, base_state=None, state_modifier=None):
    global bin_exec_initialized
    if not bin_exec_initialized:
        EmptyLibrary().install()
        random.seed(10) # not sure if this is useful, but just in case...
        faulthandler.enable()
        bin_exec_initialized = True

    # No explicit globals (we use metadata instead)
    SimState.register_default("globals", DummyPlugin)
    # No explicit heap (we use our memory's "allocate" instead)
    SimState.register_default("heap", DummyPlugin)
    # Our plugins
    SimState.register_default("metadata", MetadataPlugin)
    SimState.register_default("maps", GhostMapsPlugin)
    SimState.register_default("path", PathPlugin)
    SimState.register_default("pci", PciPlugin)
    SimState.register_default("sym_memory", CustomMemory) # Has to be named that way for angr to use it as default

    proj = angr.Project(binary, auto_load_libs=False, use_sim_procedures=False, engine=CustomEngine, simos=SimOS)
    for (fname, fproc) in ext_funcs.items():
        if proj.loader.find_symbol(fname) is not None:
            proj.hook_symbol(fname, PathPlugin.wrap(fproc()))
    # Not sure if this is needed but let's do it just in case, to make sure we don't change the base state
    base_state = base_state.copy() if base_state is not None else None
    main_func = proj.loader.find_symbol(main_func_name)
    init_state = proj.factory.call_state(main_func.rebased_addr, *main_func_args, base_state=base_state)
    # It seems there's no way around enabling these, since code can access uninitialized variables (common in the "return bool, take in a pointer to the result" pattern)
    init_state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    init_state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    if base_state is None:
        init_state.solver._stored_solver = CustomSolver()
    if state_modifier is not None:
        state_modifier(init_state)
    sm = proj.factory.simulation_manager(init_state)
    # We want exhaustive symbex, DFS makes debugging a lot easier by not interleaving paths
    sm.use_technique(angr.exploration_techniques.DFS())
    return sm
