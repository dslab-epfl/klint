from angr import SimProcedure
from angr.state_plugins.plugin import SimStatePlugin
from angr.state_plugins.sim_action import SimActionObject
import claripy
import copy
import inspect

from kalm import utils

class ExternalWrapper(SimProcedure):
    def __init__(self, wrapped):
        self.wrapped = wrapped
        SimProcedure.__init__(self)
        # fix args count (code copied from angr SimProcedure)
        run_spec = inspect.getfullargspec(self.wrapped.run)
        self.num_args = len(run_spec.args) - (len(run_spec.defaults) if run_spec.defaults is not None else 0) - 1
        self.true_display_name = self.wrapped.display_name

    def run(self, *args, **kwargs):
        self.wrapped.__dict__ = self.__dict__

        self.state.path.begin_record(self.true_display_name, [a.ast if isinstance(a, SimActionObject) else a for a in args])
        ret = self.wrapped.run(*args, **kwargs)
        # This will execute for the current state in case the procedure forked, not the other one;
        # to handle the other one, we explicitly deal with it in utils.fork
        self.state.path.end_record(ret)
        return ret


class PathPlugin(SimStatePlugin):
    def __init__(self, _segments=[]):
        SimStatePlugin.__init__(self)
        self._segments = _segments

    @SimStatePlugin.memo
    def copy(self, memo):
        return PathPlugin(_segments=self._segments.copy())

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

    @staticmethod
    def wrap(external):
        return ExternalWrapper(external)


    def begin_record(self, name, args):
        self._segments.append((name, args, None, claripy.true))

    def end_record(self, ret):
        (name, args, _, cond) = self._segments.pop()
        self._segments.append((name, args, ret, cond))

    def clear(self):
        self._segments = []
