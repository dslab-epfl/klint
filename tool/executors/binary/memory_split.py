import angr
from angr.state_plugins.plugin import SimStatePlugin
from angr.state_plugins.symbolic_memory import SimSymbolicMemory
from angr.storage.memory import SimMemory
from executors.binary.memory_fractional import FractionalMemory
from collections import namedtuple

# Supports loads and stores; forwards any unknown method to the abstract memory
class SplitMemory(SimMemory):
    def __init__(self, memory_id='', memory_backer=None, permissions_backer=None, endness=None, abstract_memory=None, concrete_memory=None):
        SimMemory.__init__(self, endness=endness, abstract_backer=None, stack_region_map=None, generic_region_map=None)
        self.abstract_memory = FractionalMemory(memory_id=memory_id, endness=endness) if abstract_memory is None else abstract_memory
        self.concrete_memory = SimSymbolicMemory(memory_id=memory_id, memory_backer=memory_backer, permissions_backer=permissions_backer, endness=endness) if concrete_memory is None else concrete_memory

    def set_state(self, state):
        SimMemory.set_state(self, state)
        self.abstract_memory.set_state(state)
        self.concrete_memory.set_state(state)

    @SimStatePlugin.memo
    def copy(self, memo):
        return SplitMemory(memory_id=self.id, abstract_memory=self.abstract_memory.copy(memo), concrete_memory=self.concrete_memory.copy(memo), endness=self.endness)

    def merge(self, others, merge_conditions, common_ancestor=None):
        if any(o.id != self.id for o in others) or any(o.endness != self.endness for o in others):
            raise "Merging SplitMemory instances with different IDs or endnesses is not supported"

        self.abstract_memory.merge([o.abstract_memory for o in others], merge_conditions, common_ancestor=common_ancestor.abstract_memory if common_ancestor is not None else None)
        self.concrete_memory.merge([o.concrete_memory for o in others], merge_conditions, common_ancestor=common_ancestor.concrete_memory if common_ancestor is not None else None)
        return True

    def _get_memory(self, addr):
        return self.abstract_memory if not isinstance(addr, int) and addr.symbolic else self.concrete_memory

    def _store(self, request):
        self._get_memory(request.addr)._store(request)

    def _load(self, addr, size, condition=None, fallback=None, inspect=True, events=True, ret_on_segv=False):
        return self._get_memory(addr)._load(addr, size, condition=condition, fallback=fallback, inspect=inspect, events=events, ret_on_segv=ret_on_segv)

    def _find(self, start, what, max_search=None, max_symbolic_bytes=None, default=None, step=1, disable_actions=False, inspect=True, chunk_size=None):
        raise NotImplementedError() # hard to split; do we need it?

    def _copy_contents(self, dst, src, size, condition=None, src_memory=None, dst_memory=None, inspect=True, disable_actions=False):
        raise NotImplementedError() # hard to split unless both src and dst are concrete or both symbolic; do we need it?

    def __getattr__(self, attr):
        if hasattr(self.concrete_memory, attr):
            return getattr(self.concrete_memory, attr)
        return getattr(self.abstract_memory, attr)

    def __contains__(self, item): # used by angr internally
        return item in self.concrete_memory
