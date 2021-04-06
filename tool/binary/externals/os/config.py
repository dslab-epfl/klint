# Standard/External libraries
import angr
import claripy
from collections import namedtuple

# Us
from ... import bitsizes
from ... import cast
from binary.metadata import MetadataPlugin
from ... import utils
from ...exceptions import SymbexException

ConfigMetadata = namedtuple('ConfigMetadata', ['items'])

# TODO: also model failure case

# bool os_config_try_get(const char* name, uintmax_t* out_value);
class os_config_try_get(angr.SimProcedure):
    def run(self, name, out_value):
        name = cast.ptr(name)
        out_value = cast.ptr(out_value)

        if name.symbolic:
            raise SymbexException("name cannot be symbolic")

        self.state.memory.load(out_value, bitsizes.uintmax_t // 8)

        py_name = utils.read_str(self.state, name)
        metadata = self.state.metadata.get(ConfigMetadata, MetadataPlugin.UNIQUE_ID, default_ctor=lambda: ConfigMetadata({}))
        if py_name not in metadata.items:
            value = claripy.BVS(py_name, bitsizes.uintmax_t)
            metadata.items[py_name] = value

        self.state.memory.store(out_value, metadata.items[py_name], endness=self.state.arch.memory_endness)
        return claripy.BVV(1, bitsizes.bool)
