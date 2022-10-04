import angr
from angr.state_plugins.plugin import SimStatePlugin

# Convenience plugin to resolve the size of specific types


class SizesPlugin(SimStatePlugin):
    def set_state(self, state):
        for (n, t) in angr.types.ALL_TYPES.items():
            try:
                setattr(self, n, t.with_arch(state.arch).size)
            except ValueError:
                # skip failing types, angr/angr#3551
                pass
        return super().set_state(state)

    # shorthand
    @property
    def ptr(self):
        return self.uintptr_t

    @SimStatePlugin.memo
    def copy(self, memo):
        return SizesPlugin()

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True
