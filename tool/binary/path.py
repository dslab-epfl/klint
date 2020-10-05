# Standard/External libraries
from angr import SimProcedure
from angr.state_plugins.plugin import SimStatePlugin
from angr.state_plugins.sim_action import SimActionObject
import inspect

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
        # to handle the other one, we explicitly deal with it in utils.fork_always
        self.state.path.end_record(ret)
        return ret


class Path(SimStatePlugin):
    def __init__(self, segments=None):
        SimStatePlugin.__init__(self)
        self.segments = segments or []

    @SimStatePlugin.memo
    def copy(self, memo):
        return Path(segments=self.segments.copy())

    def merge(self, others, merge_conditions, common_ancestor=None):
        self.segments = [] if common_ancestor is None else common_ancestor.segments
        return True

    @staticmethod
    def wrap(external):
        return ExternalWrapper(external)
    
    def begin_record(self, name, args):
        self.segments.append((name, args))

    def end_record(self, ret):
        (name, args) = self.segments.pop()
        self.segments.append((name, args, ret))

    def print(self, filter=None):
        for (name, args, ret) in self.segments:
            if filter is None or filter(name):
                print("  " + name + "(" + ", ".join(map(str, args)) + ")" + ("" if ret is None else (" -> " + str(ret))))