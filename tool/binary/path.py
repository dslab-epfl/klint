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
    def __init__(self, segments=None, ghost_segments=None, ghost_enabled=True):
        SimStatePlugin.__init__(self)
        self.segments = segments or []
        self.ghost_segments = ghost_segments or []
        self.ghost_enabled = ghost_enabled

    @SimStatePlugin.memo
    def copy(self, memo):
        return Path(segments=self.segments.copy(), ghost_segments=self.ghost_segments.copy(), ghost_enabled=self.ghost_enabled)

    def merge(self, others, merge_conditions, common_ancestor=None):
        self.segments = [] if common_ancestor is None else common_ancestor.segments
        self.ghost_segments = [] if common_ancestor is None else common_ancestor.ghost_segments
        self.ghost_enabled = True # re-enable regardless
        return True

    @staticmethod
    def wrap(external):
        return ExternalWrapper(external)
    
    def begin_record(self, name, args):
        self.segments.append((name, args))

    def end_record(self, ret):
        (name, args) = self.segments.pop()
        self.segments.append((name, args, ret))

    def print(self):
        for (name, args, ret) in self.segments:
            print("  ", name, "(", ", ".join(map(str, args)) + ")", ("" if ret is None else (" -> " + str(ret))))

    def ghost_record(self, value_factory):
        if self.ghost_enabled:
            self.ghost_segments.append(value_factory())

    def ghost_disable(self):
        self.ghost_enabled = False

    def ghost_print(self):
        for value in self.ghost_segments:
            print("  ", value)