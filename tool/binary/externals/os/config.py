import angr
import claripy
from collections import namedtuple

from binary.metadata import MetadataPlugin
from ... import utils

ConfigMetadata = namedtuple('ConfigMetadata', ['items'])

# TODO: also model failure case

# bool os_config_try_get(const char* name, uint64_t* out_value);
class os_config_try_get(angr.SimProcedure):
    def run(self, name, out_value):
        name = self.state.casts.ptr(name)
        out_value = self.state.casts.ptr(out_value)

        if name.symbolic:
            raise Exception("name cannot be symbolic")

        self.state.memory.load(out_value, state.sizes.uint64_t // 8)

        py_name = utils.read_str(self.state, name)
        metadata = self.state.metadata.get(ConfigMetadata, None, default_init=lambda: ConfigMetadata({}))
        if py_name not in metadata.items:
            value = claripy.BVS(py_name, state.sizes.uint64_t)
            metadata.items[py_name] = value

        self.state.memory.store(out_value, metadata.items[py_name], endness=self.state.arch.memory_endness)
        return claripy.BVV(1, state.sizes.bool)
