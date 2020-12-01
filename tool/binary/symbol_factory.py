# Standard/External libraries
from angr.state_plugins.plugin import SimStatePlugin
import claripy

# Use this within externals so that they can be replayed
# But ONLY within externals, e.g. ghost maps shouldn't use it since the maps plugin is replaced during replay
class SymbolFactoryPlugin(SimStatePlugin):
    def __init__(self, history=None):
        SimStatePlugin.__init__(self)
        self.history = history or []

    @SimStatePlugin.memo
    def copy(self, memo):
        return SymbolFactoryPlugin(self.history)

    def merge(self, others, merge_conditions, common_ancestor=None):
        self.history = []
        return True

    def BVS(self, name, size):
        result = claripy.BVS(name, size)
        self.history.append((name, result))
        return result
