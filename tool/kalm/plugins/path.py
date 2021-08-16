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
        return PathPlugin(_segments=copy.deepcopy(self._segments, memo))

    def merge(self, others, merge_conditions, common_ancestor=None):
        # Merging should never fail because of this, it's a debug thing
        self._segments = [(n, a, r, c & merge_conditions[0]) for (n, a, r, c) in self._segments]
        for (i, o) in enumerate(others):
            self._segments.extend([(n, a, r, c & merge_conditions[i + 1]) for (n, a, r, c) in o._segments])
        return True

    @staticmethod
    def wrap(external):
        return ExternalWrapper(external)
    

    def begin_record(self, name, args):
        self._segments.append((name, args, None, claripy.true))

    def end_record(self, ret):
        (name, args, _, cond) = self._segments.pop()
        self._segments.append((name, args, ret, cond))


    def print(self):
        for (name, args, ret) in self._segments:
            print("  ", name, "(", ", ".join(map(str, args)) + ")", ("" if ret is None else (" -> " + str(ret))), ("cond: " + str(cond)))