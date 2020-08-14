import angr
from angr.state_plugins.plugin import SimStatePlugin
from angr.storage.memory import SimMemory
from angr.storage.memory import MemoryStoreRequest
import archinfo
import claripy
from executors.binary.memory_segmented import SegmentedMemory
import executors.binary.bitsizes as bitsizes
import executors.binary.utils as utils
from collections import namedtuple

Facts = namedtuple('Facts', ['fractions', 'size'])


# Supports loads and stores, as well as allocate and take/give; all methods take sizes in bytes
# Handles endness, but stores data as LE instead of BE for x86 convenience;
# to do this, we reverse on store if BE is requested, and always reverse on load since SimMemory will reverse again if LE is requested
class FractionalMemory(SimMemory):
    FRACS_NAME = "fracs"

    def __init__(self, memory_id='', memory=None, fractions_memory=None, endness=None):
        SimMemory.__init__(self, endness=endness, abstract_backer=None, stack_region_map=None, generic_region_map=None)
        self.id = memory_id # magic! needs to be set for SimMemory to work
        self.memory = SegmentedMemory(memory_id) if memory is None else memory
        self.fractions_memory = SegmentedMemory(memory_id) if fractions_memory is None else fractions_memory

    def set_state(self, state):
        SimMemory.set_state(self, state)
        self.memory.set_state(state)
        self.fractions_memory.set_state(state)

    @SimStatePlugin.memo
    def copy(self, memo):
        return FractionalMemory(memory_id=self.id, memory=self.memory.copy(memo), fractions_memory=self.fractions_memory.copy(memo), endness=self.endness)

    def merge(self, others, merge_conditions, common_ancestor=None):
        if any(o.id != self.id for o in others) or any(o.endness != self.endness for o in others):
            raise "Merging FractionalMemory instances with different IDs or endnesses is not supported"

        self.memory.merge([o.memory for o in others], merge_conditions, common_ancestor=common_ancestor.memory if common_ancestor is not None else None)
        self.fractions_memory.merge([o.fractions_memory for o in others], merge_conditions, common_ancestor=common_ancestor.fractions_memory if common_ancestor is not None else None)
        return True


    # This method handles endness on its own
    def _store(self, request): # request is MemoryStoreRequest; has addr, data=None, size=None, condition=None, endness + "completed" must be set to True
        (base, index, _) = self.memory.base_index_offset(request.addr)
        facts = self.state.metadata.get(Facts, base)
        fraction = self.fractions_memory.load(facts.fractions + index, 1)
        if utils.can_be_true(self.state.solver, fraction != 100):
            raise ("Attempt to store without definitely owning the object at addr " + str(request.addr) + " ; fraction is " + str(fraction) + " ; constraints are " + str(self.state.solver.constraints) + " ; e.g. could be " + str(self.state.solver.eval_upto(fraction, 10, cast_to=int)))

        endness = self.endness if request.endness is None else request.endness
        if endness == archinfo.Endness.BE:
            request.data = request.data.reversed
        request.endness = archinfo.Endness.BE
        self.memory._store(request)

    # This method only partly handles endness; SimMemory will reverse if (endness or self.endness) is LE
    def _load(self, addr, size, condition=None, fallback=None, inspect=True, events=True, ret_on_segv=False):
        (base, index, _) = self.memory.base_index_offset(addr)
        facts = self.state.metadata.get(Facts, base)
        fraction = self.fractions_memory.load(facts.fractions + index, 1)
        if utils.can_be_true(self.state.solver, fraction == 0):
            raise ("Attempt to load without definitely having access to the object at addr " + str(addr) + " ; fraction is " + str(fraction) + " ; constraints are " + str(self.state.solver.constraints) + " ; e.g. could be " + str(self.state.solver.eval_upto(fraction, 10, cast_to=int)))
        (addr, value, constrs) = self.memory._load(addr, size, condition=condition, fallback=fallback, inspect=inspect, events=events, ret_on_segv=ret_on_segv)
        return (addr, value.reversed, constrs)

    def _find(self, start, what, max_search=None, max_symbolic_bytes=None, default=None, step=1, disable_actions=False, inspect=True, chunk_size=None):
        raise NotImplementedError() # do we need this?

    def _copy_contents(self, dst, src, size, condition=None, src_memory=None, dst_memory=None, inspect=True, disable_actions=False):
        raise NotImplementedError() # do we need this?

    def allocate(self, count, size, default=None, name=None):
        result = self.memory.allocate(count, size, default=default, name=name)
        fractions = self.fractions_memory.allocate(count, 1, claripy.BVV(100, 8), name=((name or "") + FractionalMemory.FRACS_NAME))
        self.state.metadata.set(result, Facts(fractions, size))
        return result

    def allocate_opaque(self, name):
        result = claripy.BVS(name + "_opaque", bitsizes.PTR)
        self.state.add_constraints(result != 0)
        return result

    def take(self, fraction, ptr, size): # fraction == None -> take all
        (base, index, offset) = self.memory.base_index_offset(ptr)
        if offset != 0:
            raise "Cannot take at an offset"

        facts = self.state.metadata.get(Facts, base)
        if utils.can_be_true(self.state.solver, facts.size != size):
            raise ("Can only take entire items ; you wanted " + str(size) + " but the item size is " + str(facts.size))

        current_fraction = self.fractions_memory.load(facts.fractions + index, 1)
        if fraction is None:
            fraction = current_fraction

        if utils.can_be_true(self.state.solver, current_fraction.ULT(fraction)):
            raise ("Cannot take " + str(fraction) + " ; there is only " + str(current_fraction))

        self.fractions_memory.store(facts.fractions + index, (current_fraction - fraction), size=1)
        return current_fraction

    def give(self, fraction, ptr, size):
        (base, index, offset) = self.memory.base_index_offset(ptr)
        if offset != 0:
            raise ("Cannot give at an offset")

        facts = self.state.metadata.get(Facts, base)
        if utils.can_be_true(self.state.solver, facts.size != size):
            raise ("Can only give entire items ; you wanted " + str(size) + " but the item size is " + str(fact.size))

        current_fraction = self.fractions_memory.load(facts.fractions + index, 1)
        if utils.can_be_true(self.state.solver, (current_fraction + fraction).UGT(100)):
            raise ("Cannot give " + str(fraction) + " ; there is already " + str(current_fraction))

        self.fractions_memory.store(facts.fractions + index, (current_fraction + fraction), size=1)

    # here we don't handle endness
    # TODO handle it for non-x86 targets (we currently store as LE)
    def try_load(self, addr, fraction=None, from_present=True, _cache={}):
        # Caching is a requirement, not an optimization;
        # without it, the "bad_value" is different every time, so try_load(addr) != try_load(addr)
        if id(addr) not in _cache:
            (base, index, _) = self.memory.base_index_offset(addr)
            facts = self.state.metadata.get(Facts, base)
            if fraction is None:
                fraction = self.fractions_memory.try_load(facts.fractions + index, 1, from_present=from_present)
            value = self.memory.try_load(addr, facts.size, from_present=from_present)
            _cache[id(addr)] = claripy.If(fraction > 0, value, claripy.BVS("memory_fractional_bad_value", value.size()))
        return _cache[id(addr)]

    def get_obj_and_size_from_fracs_obj(self, fracs_obj):
        if FractionalMemory.FRACS_NAME not in str(fracs_obj):
            return (None, None)
        for (o, facts) in self.state.metadata.get_all(Facts):
            if facts.fractions is fracs_obj:
                return (o, facts.size)
        raise "What are you doing?"