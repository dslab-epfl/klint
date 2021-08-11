from angr.engines.failure import SimEngineFailure
from angr.engines.hook import HooksMixin
from angr.engines.vex import HeavyVEXMixin

# Keep only what we need in the engine, and handle in, out, rdtsc
# Also, special-case hlt into the 'trapped_states' global
class KalmEngine(SimEngineFailure, HooksMixin, HeavyVEXMixin):
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
            (_, cycles) = clock.get_time_and_cycles(self.state)
            return cycles

        raise angr.errors.UnsupportedDirtyError("Unexpected angr 'dirty' call")


    def process_successors(self, successors, **kwargs):
        state = self.state
        jumpkind = state.history.parent.jumpkind if state.history and state.history.parent else None
        if jumpkind == 'Ijk_SigTRAP': # we hit a 'hlt'
            global trapped_states
            trapped_states.append(state)
            return None
        super().process_successors(successors, **kwargs)