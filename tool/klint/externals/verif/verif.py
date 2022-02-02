import angr
from angr.sim_type import ALL_TYPES, SimTypeFunction, SimTypeTop
import claripy

from kalm import utils
from kalm import executor as binary_executor
from klint import executor as nf_executor
from klint.fullstack import device as nf_device


def _custom_memory(memory_count, memory_size): # size in bits
    def reader(state, base, index, offset, size, reverse_endness):
        if size is None:
            size = memory_size
        else:
            size = size * 8
        index = utils.get_if_constant(state.solver, index)
        assert index is not None
        assert index < memory_count

        memory = state.metadata.get(type({}), base, default_init=lambda: {})

        result = memory.setdefault(index, claripy.BVV(0, memory_size))[offset+size-1:offset]
        if reverse_endness:
            result = result.reversed
        return result

    def writer(state, base, index, offset, value, reverse_endness):
        index = utils.get_if_constant(state.solver, index)
        assert index is not None
        assert index < memory_count

        memory = state.metadata.get(type({}), base, default_init=lambda: {})

        existing_value = memory.setdefault(index, claripy.BVV(0, memory_size))
        if reverse_endness:
            existing_value = existing_value.reversed
        if offset != 0:
            value = value.concat(existing_value[offset-1:0])
        if value.size() != memory_size:
            value = existing_value[:value.size()].concat(value)
        if reverse_endness:
            value = value.reversed
        memory[index] = value

    return (reader, writer)



# uint64_t* descriptor_ring_alloc(size_t count);
class descriptor_ring_alloc(angr.SimProcedure):
    def run(self, count):
        count = self.state.casts.size_t(count)

        concrete_count = utils.get_if_constant(self.state.solver, count)
        assert concrete_count is not None

        (ring_reader, ring_writer) = _custom_memory(concrete_count, self.state.sizes.uint64_t * 2)
        obj = claripy.BVS("descriptor_ring", self.state.sizes.ptr)
        self.state.memory.set_special_object(obj, concrete_count, (self.state.sizes.uint64_t * 2) // 8, ring_reader, ring_writer)
        return obj

# void* agents_alloc(size_t count, size_t size);
class agents_alloc(angr.SimProcedure):
    def run(self, count, size):
        count = self.state.casts.size_t(count)
        size = self.state.casts.size_t(size)

        concrete_count = utils.get_if_constant(self.state.solver, count)
        assert concrete_count is not None
        concrete_size = utils.get_if_constant(self.state.solver, size)
        assert concrete_size is not None

        (reader, writer) = _custom_memory(concrete_count, concrete_size * 8)
        obj = claripy.BVS("agents", self.state.sizes.ptr)
        self.state.memory.set_special_object(obj, concrete_count, concrete_size, reader, writer)
        return obj

# typedef void foreach_index_forever_function(size_t index, void* state);
# _Noreturn void foreach_index_forever(size_t length, foreach_index_forever_function* func, void* state);
class foreach_index_forever(angr.SimProcedure):
    NO_RET = True # magic angr variable

    @staticmethod
    def state_creator(st, index, func, func_st):
        nf_device.receive_packet_on_device(st, index)
        return binary_executor.create_calling_state(st, func, SimTypeFunction([ALL_TYPES['size_t'], SimTypeTop()], None), [index, func_st], nf_executor.nf_handle_externals)

    def run(self, length, func, func_st):
        length = self.state.casts.size_t(length)
        func = self.state.casts.ptr(func)
        func_st = self.state.casts.ptr(func_st)

        if func.op != 'BVV':
            raise Exception("Function pointer cannot be symbolic")
        self.state.solver.add(length.UGT(0))

        # Ideally:
        #index = claripy.BVS("foreach_index", self.state.sizes.size_t)
        #self.state.solver.add(index.ULT(length))
        # But:
        concrete_length = utils.get_if_constant(self.state.solver, length)
        assert length is not None
        for idx in range(concrete_length):
            index = claripy.BVV(idx, self.state.sizes.size_t)
            creator = lambda st, index=index: foreach_index_forever.state_creator(st, index, func, func_st) 
            nf_executor.nf_inited_states.append((self.state, creator))

        self.exit(0)
