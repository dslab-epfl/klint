import angr
import claripy

from binary import executor as binary_executor
from nf import executor as nf_executor


# uint64_t* descriptor_ring_alloc(size_t count);
class descriptor_ring_alloc(angr.SimProcedure):
    def run(self, count):
        count = self.state.casts.size_t(count)

        ring_array = {}
        def ring_reader(state, base, index, offset, size):
            if size is None:
                size = (state.sizes.uint64_t * 2)
            else:
                size = size * 8
            assert not index.symbolic
            index = state.solver.eval(index)
            return ring_array[index][size-1:offset]

        def ring_writer(state, base, index, offset, value):
            assert not index.symbolic
            index = state.solver.eval(index)
            existing_value = ring_array.get(index, claripy.BVV(0, state.sizes.uint64_t * 2))
            if offset != 0:
                value = value.concat(existing_value[offset-1:0])
            if value.size() != state.sizes.uint64_t * 2:
                value = existing_value[:value.size()].concat(value)
            ring_array[index] = value

        return self.state.memory.create_special_object("descriptor_ring", count, (self.state.sizes.uint64_t * 2) // 8, ring_reader, ring_writer)


# typedef void foreach_index_forever_function(size_t index, void* state);
# _Noreturn void foreach_index_forever(size_t length, foreach_index_forever_function* func, void* state);
class foreach_index_forever(angr.SimProcedure):
    NO_RET = True # magic angr variable

    def run(self, length, func, st):
        length = self.state.casts.size_t(length)
        func = self.state.casts.ptr(func)
        st = self.state.casts.ptr(st)

        if func.op != 'BVV':
            raise Exception("Function pointer cannot be symbolic")
        self.state.solver.add(length.UGT(0))

        index = claripy.BVS("foreach_index", self.state.sizes.size_t)
        self.state.solver.add(index.ULT(length))

        func_state = binary_executor.create_calling_state(self.state, func, [index, st], nf_executor.nf_handle_externals)
        nf_executor.nf_inited_states.append(func_state)

        self.exit(0)
