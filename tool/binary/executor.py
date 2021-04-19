import faulthandler
import random
import angr
from angr.sim_state import SimState
from angr.simos import SimOS
import claripy

from . import clock
from . import merging_technique
from .casts import CastsPlugin
from .ghost_maps import GhostMapsPlugin
from .maps_memory import MapsMemoryMixin
from .metadata import MetadataPlugin
from .objs_memory import ObjectsMemoryMixin
from .path import PathPlugin
from .pci import PciPlugin
from .plugin_dummy import DummyPlugin
from .sizes import SizesPlugin


DEBUG = False

claripy.set_debug(DEBUG)
if not DEBUG:
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
            return clock.get_current_cycles(self.state)
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

    def add(self, constraints, **kwargs):
        if DEBUG:
            for con in constraints:
                super().add([con], **kwargs)
                if not self.satisfiable():
                    raise Exception("UNSAT after adding constraint: " + str(con))
        return super().add(constraints, **kwargs)

    def simplify(self, **kwargs):
        # TODO: Investigate this. There seems to be a bug in the simplification that drops constraints
        return self.constraints
        """prev_cons = self.constraints.copy()
        result = super().simplify(**kwargs)
        if any("map_values_4_present" in str(c) and (c.op == 'BoolS' or c.op == 'Not') for c in prev_cons) and \
           not any("map_values_4_present" in str(c) and (c.op == 'BoolS' or c.op == 'Not') for c in self.constraints):
            print("what") # at this point the map present bit has 2 possible values!
        return result"""

# Keep only what we need in the memory, including our custom layers
import angr.storage.memory_mixins as csms
class CustomMemory(
    csms.NameResolutionMixin, # To allow uses of register names, which angr does internally when this is used for regs
    csms.DataNormalizationMixin, # To always get AST values
    csms.SizeNormalizationMixin, # To always get actual sizes in stores (required by some angr mixins)
    ObjectsMemoryMixin, # For modelled devices
    MapsMemoryMixin, # For the heap
    # --- Rest is inspired by DefaultMemory, minus stuff we definitely don't need; TODO: can we make this all read-only after init?
    csms.ConvenientMappingsMixin,
    csms.StackAllocationMixin,
    csms.ClemoryBackerMixin,
    csms.DictBackerMixin,
    csms.UltraPagesMixin,
    csms.DefaultFillerMixin,
    csms.PagedMemoryMixin
):
    def _merge_values(self, values, merged_size):
        return claripy.ite_cases([(g, v) for (v, g) in values[1:]], values[0][0])


EmptyLibrary().install()
random.seed(10) # not sure if this is useful, but just in case...
faulthandler.enable()
# No explicit globals (we use metadata instead)
SimState.register_default("globals", DummyPlugin)
# No explicit heap (we use our memory's "allocate" instead)
SimState.register_default("heap", DummyPlugin)
# Our plugins (TODO: have a proper 'plugins' submodule, which imports them on init, and is imported by our own init, etc; use a plugin preset so we don't need the dummy!)
SimState.register_default("casts", CastsPlugin)
SimState.register_default("metadata", MetadataPlugin)
SimState.register_default("maps", GhostMapsPlugin)
SimState.register_default("path", PathPlugin)
SimState.register_default("pci", PciPlugin)
SimState.register_default("sizes", SizesPlugin)
SimState.register_default("sym_memory", CustomMemory) # Has to be named that way for angr to use it as default


def _create_project(binary_path):
    # Use the base SimOS, not any specific OS, we shouldn't depend on anything
    return angr.Project(binary_path, auto_load_libs=False, use_sim_procedures=False, engine=CustomEngine, simos=SimOS)


def create_blank_state(binary_path):
    proj = _create_project(binary_path)
    state = proj.factory.blank_state()
    # It seems there's no way around enabling these, since code can access uninitialized variables (common in the "return bool, take in a pointer to the result" pattern)
    state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    state.solver._stored_solver = CustomSolver()
    return state

def create_calling_state(state, function_thing, function_args, externals):
    # Re-create a project, since we may need different externals than last time
    new_proj = _create_project(state.project.filename)
    # Add our externals
    for (name, proc) in externals.items():
        if state.project.loader.find_symbol(name) is not None:
            state.project.hook_symbol(name, PathPlugin.wrap(proc()))
    # Create the state
    if isinstance(function_thing, str):
        function = state.project.loader.find_symbol(function_thing)
    else:
        function = function_thing
    return state.project.factory.call_state(function.rebased_addr, *function_args, base_state=state)

def run_state(state):
    sm = state.project.factory.simulation_manager(state)
    sm.use_technique(merging_technique.MergingTechnique())
    sm.run()
    if len(sm.errored) > 0:
        print("Error, e.g. at", sm.errored[0].state.regs.rip)
        sm.errored[0].reraise()
    # We do not ever expect unsat states; this could mean e.g. a precondition was not met
    if len(sm.unsat) > 0:
        raise Exception("There are unsat states! e.g. " + ", ".join([str(c) for c in sm.unsat[0].solver.constraints]))
    return sm.deadended