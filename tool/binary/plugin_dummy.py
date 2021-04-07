from angr.state_plugins.plugin import SimStatePlugin

# Nothing; just ensures angr doesn't use plugins behind our back
class DummyPlugin(SimStatePlugin):
    @SimStatePlugin.memo
    def copy(self, memo):
        return self

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True
