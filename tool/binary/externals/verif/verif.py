import angr
import claripy


# uint64_t* descriptor_ring_alloc(size_t size);
class descriptor_ring_alloc(angr.SimProcedure):
    def run(self, size):
        size = self.state.casts.size_t(size)
        ring = claripy.BVS("descriptor_ring", self.state.sizes.ptr)


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
        print("ok")