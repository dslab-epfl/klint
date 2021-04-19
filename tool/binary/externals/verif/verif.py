import angr
import claripy


# uint64_t* descriptor_ring_alloc(size_t count);
class descriptor_ring_alloc(angr.SimProcedure):
    def run(self, count):
        count = self.state.casts.size_t(count)

        ring_array = {}
        def ring_reader(state, base, index, offset, size):
            if size is None:
                size = (state.sizes.uint64_t * 2) // 8
            value = ring_array[index][size-1:offset]

        def ring_writer(state, base, index, offset, value):
            existing_value = ring_array[index]
            if offset != 0:
                value = value.concat(existing_value[offset-1:0])
            if value.size() != (state.sizes.uint64_t * 2) // 8:
                value = existing_value[:value.size()].concat(value)
            ring_array[index] = value

        return self.state.memory.create_special_object("descriptor_ring", count, (self.state.sizes.uint64_t * 2) // 8, ring_reader, ring_writer)


# typedef void foreach_index_forever_function(size_t index, void* state);
# _Noreturn void foreach_index_forever(size_t length, foreach_index_forever_function* func, void* state);
class foreach_index_forever(angr.SimProcedure):
    def run(self, length, func, st):
        length = self.state.casts.size_t(length)
        func = self.state.casts.ptr(func)
        st = self.state.casts.ptr(st)

        if func.op != 'BVV':
            raise Exception("Function pointer cannot be symbolic")
        state.solver.add(length.UGT(0))

        index = claripy.BVS("foreach_index", self.state.sizes.size_t)
        self.state.solver.add(index.ULT(length))
        func_state = self.state.project.factory.call_state(func.args[0], *[index, st], base_state=self.state)
        func_sm = self.state.project.factory.simulation_manager(func_state)
        func_sm.use_technique(angr.exploration_techniques.DFS())
        func_sm.run()
        if len(func_sm.errored) > 0:
            func_sm.errored[0].reraise()
        if len(func_sm.unsat) > 0:
            raise Exception("UNSAT!")
        print("ok")