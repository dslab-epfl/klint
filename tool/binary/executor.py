# Standard/External libraries
import faulthandler
import random
import angr
from angr.sim_state import SimState
from angr.simos import SimOS

# Us
from . import clock
from .exceptions import SymbexException
from .ghost_maps import GhostMapsPlugin
from .memory_split import SplitMemory
from .metadata import MetadataPlugin
from .path import PathPlugin
from .pci import PciPlugin
from .plugin_dummy import DummyPlugin
from .symbol_factory import SymbolFactoryPlugin

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
            raise SymbexException('Unimplemented function')

    def __init__(self):
        # the existence of syscall_number_mapping and minimum/maximum_syscall_number is required by angr
        pass #self.syscall_number_mapping = ['i386', 'amd64']

    def install(self):
        # remove everything else
        angr.SIM_LIBRARIES.clear()
        angr.SIM_PROCEDURES.clear()
        # set ourselves as a library
        angr.SIM_LIBRARIES['externals'] = self
        # angr expects some specific libraries to exist
        #angr.SIM_LIBRARIES['linux'] = self
        #angr.SIM_LIBRARIES['ld.so'] = self
        #angr.SIM_LIBRARIES['libc.so.6'] = self
        # angr hardcodes some linux procedures
        #angr.SIM_PROCEDURES['linux_loader'] = {
        #    'LinuxLoader': EmptyLibrary.Abort,
        #    '_dl_rtld_lock_recursive': EmptyLibrary.Abort,
        #    '_dl_rtld_unlock_recursive': EmptyLibrary.Abort,
        #    '_dl_initial_error_catch_tsd': EmptyLibrary.Abort
        #}
        #angr.SIM_PROCEDURES['linux_kernel'] = {
        #    '_vsyscall': EmptyLibrary.Abort
        #}
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

    # no syscalls available
    #def minimum_syscall_number(self, abi): return 0
    #def maximum_syscall_number(self, abi): return 0


# Keep only what we need in the engine, and handle hlt and in/out
from angr.engines.failure import SimEngineFailure
from angr.engines.hook import HooksMixin
from angr.engines.vex import HeavyVEXMixin
class CustomEngine(SimEngineFailure, HooksMixin, HeavyVEXMixin):
    def _perform_vex_defaultexit(self, expr, jumpkind):
        if jumpkind != 'Ijk_SigTRAP': # TRAP means the program executed an invalid instr like 'hlt'; just stop in that case, no error
            super()._perform_vex_defaultexit(expr, jumpkind)

    def _handle_vex_stmt(self, stmt):
        print(type(stmt), stmt)
        super()._handle_vex_stmt(stmt)

    def _perform_vex_stmt_Dirty_call(self, func_name, ty, args, func=None):
        if func_name == "amd64g_dirtyhelper_IN":
            # args = [portno (16b), size]
            if args[0].op != 'BVV':
                raise angr.errors.UnsupportedDirtyError("Symbolic port for 'in'")
            port = args[0].args[0]
            if args[1].op != 'BVV':
                raise angr.errors.UnsupportedDirtyError("Symbolic size for 'in'")
            size = args[1].args[0]
            return self.state.pci.handle_in(port, size)
        if func_name == "amd64g_dirtyhelper_OUT":
            # args = [portno (16b), data (32b), size]
            if args[0].op != 'BVV':
                raise angr.errors.UnsupportedDirtyError("Symbolic port for 'out'")
            port = args[0].args[0]
            if args[2].op != 'BVV':
                raise angr.errors.UnsupportedDirtyError("Symbolic size for 'out'")
            size = args[2].args[0]
            data = args[1][size*8-1:0]
            self.state.pci.handle_out(port, data, size)
            return None

        #if func_name == 'amd64g_dirtyhelper_RDTSC':
        #    return clock.get_current_time(self.state)
        return super()._perform_vex_stmt_Dirty_call(func_name, ty, args, func=func)
        #raise angr.errors.UnsupportedDirtyError("Unexpected angr 'dirty' call")

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
        super(CustomSolver, self).__init__(template_solver, template_solver_string, track=track, **kwargs)

bin_exec_initialized = False

def create_sim_manager(binary, ext_funcs, main_func_name, *main_func_args, base_state=None):
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
    SimState.register_default("sym_memory", SplitMemory) # SimState translates "sym_memory" to "memory" under standard options
    SimState.register_default("maps", GhostMapsPlugin)
    SimState.register_default("path", PathPlugin)
    SimState.register_default("pci", PciPlugin)
    SimState.register_default("symbol_factory", SymbolFactoryPlugin)

    proj = angr.Project(binary, auto_load_libs=False, use_sim_procedures=False, engine=CustomEngine, simos=SimOS)
    for (fname, fproc) in ext_funcs.items():
        if proj.loader.find_symbol(fname) is not None:
            proj.hook_symbol(fname, PathPlugin.wrap(fproc()))
    # Not sure if this is needed but let's do it just in case, to make sure we don't change the base state
    base_state = base_state.copy() if base_state is not None else None
    if main_func_name is None:
        assert base_state is None
        init_state = proj.factory.full_init_state()
    else:
        main_func = proj.loader.find_symbol(main_func_name)
        init_state = proj.factory.call_state(main_func.rebased_addr, *main_func_args, base_state=base_state)
    if base_state is None:
        init_state.solver._stored_solver = CustomSolver()
    # It seems there's no way around enabling these, since code can access uninitialized variables (common in the "return bool, take in a pointer to the result" pattern)
    init_state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    init_state.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    sm = proj.factory.simulation_manager(init_state)
    # We want exhaustive symbex, DFS makes debugging a lot easier by not interleaving paths
    sm.use_technique(angr.exploration_techniques.DFS())
    return sm
