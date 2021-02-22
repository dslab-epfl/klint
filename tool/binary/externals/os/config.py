# Standard/External libraries
import angr
import claripy
from collections import namedtuple

# Us
from ... import bitsizes
from ... import cast
from ... import utils
from ...exceptions import SymbexException

ConfigMetadata = namedtuple('ConfigMetadata', ['items'])

# bool os_config_get(const char* name, uintmax_t* out_value);
class os_config_get(angr.SimProcedure):
    def run(self, name, out_value):
        name = cast.ptr(name)
        out_value = cast.ptr(out_value)

        if name.symbolic:
            raise SymbexException("name cannot be symbolic")

        py_name = utils.read_str(self.state, name)
        metadata = self.state.metadata.get(ConfigMetadata, None, default=ConfigMetadata({}))
        if py_name not in metadata.items:
            value = claripy.BVS(py_name, bitsizes.uintmax_t) # not using symbol_factory since this is not replayed
            metadata.items[py_name] = value

        value = metadata.items[py_name]

        return value