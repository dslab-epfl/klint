import angr
from angr.sim_type import *
import claripy
from collections import namedtuple

from kalm import utils

ConfigMetadata = namedtuple('ConfigMetadata', ['items'])

# bool os_config_try_get(const char* name, uint64_t* out_value);
class os_config_try_get(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeChar()), SimTypePointer(SimTypeNum(64, False))], SimTypeBool(), arg_names=["name", "out_value"])

    def run(self, name, out_value):
        if name.symbolic:
            raise Exception("name cannot be symbolic")

        # Precondition: name and out_value are accessible
        py_name = utils.read_str(self.state, name)
        self.state.memory.load(out_value, 64 // 8)

        def case_true(state):
            metadata = state.metadata.get(ConfigMetadata, None, default_init=lambda: ConfigMetadata({}))
            if py_name not in metadata.items:
                value = claripy.BVS(py_name, 64)
                metadata.items[py_name] = value
            state.memory.store(out_value, metadata.items[py_name], endness=state.arch.memory_endness)
            return claripy.BVV(1, self.prototype.returnty.size)

        def case_false(state):
            return claripy.BVV(0, self.prototype.returnty.size)

        return utils.fork_guarded(self, self.state, claripy.BoolS("config_has_" + py_name), case_true, case_false)
