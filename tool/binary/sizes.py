import angr
from angr.state_plugins.plugin import SimStatePlugin

# note: as of 09/04/2021 you can't add 'intmax_t' or 'uintmax_t' because angr typedefs them to int/unsigned int for some reason
TYPES = [
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "size_t"
]

ALIASES = [
    ("bool", "char"), # angr really should support this...
    ("ptr", "void*")
]

class SizesPlugin(SimStatePlugin):
    _RESOLVED_TYPES = [(t, angr.types.parse_type(t)) for t in TYPES] + [(n, angr.types.parse_type(t)) for (n, t) in ALIASES]

    def set_state(self, state):
        for (n, t) in SizesPlugin._RESOLVED_TYPES:
            setattr(self, n, t.with_arch(state.arch).size)
        return super().set_state(state)

    @SimStatePlugin.memo
    def copy(self, memo):
        return SizesPlugin()

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True
