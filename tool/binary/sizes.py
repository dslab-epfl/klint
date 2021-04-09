import angr

# note: as of 09/04/2021 you can't add 'intmax_t' or 'uintmax_t' because angr typedefs them to int/unsigned int for some reason
TYPES = [
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "size_t"
]

ALIASES = {
    "bool": "char", # angr really should support this...
    "ptr": "void*"
}

class SizesPlugin(angr.state_plugins.plugin.SimStatePlugin):
    def set_state(self, state):
        for type in TYPES:
            setattr(self, type, angr.types.parse_type(type).with_state(state).size)
        for (name, type) in ALIASES.items():
            setattr(self, name, angr.types.parse_type(type).with_state(state).size)
        return super().set_state(state)

    @SimStatePlugin.memo
    def copy(self, memo):
        return self

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True
