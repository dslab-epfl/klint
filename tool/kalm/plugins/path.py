import angr
from angr.state_plugins.plugin import SimStatePlugin
from angr.state_plugins.sim_action import SimActionObject
import claripy
import inspect

class PathPlugin(SimStatePlugin):
    def __init__(self, _segments=[]):
        SimStatePlugin.__init__(self)
        self._segments = _segments

    @SimStatePlugin.memo
    def copy(self, memo):
        return PathPlugin(_segments=self._segments.copy())

    @staticmethod
    def bp_before(state):
        # Ignore this, we don't care
        if state.inspect.simprocedure_name == 'CallReturn': return
        inst = state.inspect.simprocedure
        # the next 2 lines were copied from the SimProcedure code
        arg_session = inst.cc.arg_session(inst.prototype.returnty)
        args = [inst.cc.next_arg(arg_session, ty).get_value(inst.state) for ty in inst.prototype.args]
        state.path.begin_record(state.inspect.simprocedure_name, args)

    @staticmethod
    def bp_after(state):
        if state.inspect.simprocedure_name == 'CallReturn': return
        # This will execute for the current state in case the procedure forked, not the other one;
        # to handle the other one, we explicitly deal with it in utils.fork
        state.path.end_record(state.inspect.simprocedure_result)

    def set_state(self, state):
        # IDK how else to not set breakpoints unnecessarily...
        if len(state.inspect._breakpoints['simprocedure']) > 0: return
        state.inspect.b('simprocedure', when=angr.BP_BEFORE, action=PathPlugin.bp_before)
        state.inspect.b('simprocedure', when=angr.BP_AFTER, action=PathPlugin.bp_after)

    def merge(self, others, merge_conditions, common_ancestor=None):
        divergence_index = 0
        min_length = min(len(self._segments), *[len(o._segments) for o in others])
        while divergence_index < min_length:
            for o in others:
                if self._segments[divergence_index] is not o._segments[divergence_index]:
                    break
            else:
                divergence_index = divergence_index + 1
                continue
            break

        merged_segments = self._segments[:divergence_index]
        for path, cond in zip([self] + others, merge_conditions):
            for (n, a, r, c) in path._segments[divergence_index:]:
                merged_segments.append((n, a, r, c & cond))

        # Merging should never fail because of this, it's a debug thing
        self._segments = merged_segments
        return True

    def begin_record(self, name, args):
        self._segments.append((name, args, None, claripy.true))

    def end_record(self, ret):
        (name, args, _, cond) = self._segments.pop()
        self._segments.append((name, args, ret, cond))

    def clear(self):
        self._segments = []
