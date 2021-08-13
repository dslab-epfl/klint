import angr
from angr.state_plugins.plugin import SimStatePlugin
from angr.state_plugins.sim_action import SimActionObject
import claripy

from kalm.plugins.sizes import TYPES, ALIASES

EXTRA = [
    "enum",
    "struct"
]

class CastsPlugin(SimStatePlugin):
    @staticmethod
    def _fix(o):
        if isinstance(o, SimActionObject):
            o = o.ast
        # HACK: Turn ((0#64 .. a) / (0#64 .. b))[63:0] into (a / b),
        #       becaus Z3 seems to really not like the 128-bit version and takes minutes to solve stuff involving it
        #       This ends up used for the cycles-to-time conversion with rdtsc
        if o.op == 'Extract' and o.args[0] == 63 and o.args[1] == 0 and o.args[2].size() == 128 and \
           o.args[2].op == '__floordiv__' and \
           o.args[2].args[1][127:64].structurally_match(claripy.BVV(0, 64)) and \
           o.args[2].args[0][127:64].structurally_match(claripy.BVV(0, 64)):
            o = o.args[2].args[0][63:0] // o.args[2].args[1][63:0]
        return o

    @SimStatePlugin.memo
    def copy(self, memo):
        return CastsPlugin()

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True

for t in TYPES:
    setattr(CastsPlugin, t, lambda self, arg, t=t: CastsPlugin._fix(arg)[getattr(self.state.sizes, t)-1:0])
for (n, t) in ALIASES:
    setattr(CastsPlugin, n, lambda self, arg, t=t: CastsPlugin._fix(arg)[getattr(self.state.sizes, n)-1:0])
for t in EXTRA:
    setattr(CastsPlugin, t, lambda self, arg: CastsPlugin._fix(arg))