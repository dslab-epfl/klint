# Standard/External libraries
import angr
from angr.state_plugins.plugin import SimStatePlugin
from angr.storage.memory import SimMemory
from angr.storage.memory import MemoryStoreRequest
import archinfo
import claripy
from collections import namedtuple
import copy

# Us
from binary.hash_dict import HashDict
from .exceptions import SymbexException
from .memory_segmented import SegmentedMemory
from . import bitsizes
from . import utils

# TODO: Only query the fractions map if 'take' has been called at least once for it; but this means Facts may not be the same before/after init, how to handle that?
Facts = namedtuple('Facts', ['fractions', 'size'])
RecordAllocateOpaque = namedtuple('RecordAllocateOpaque', ['name', 'result'])


# Supports loads and stores, as well as allocate and take/give; all methods take sizes in bytes
# Handles endness, but stores data as LE instead of BE for x86 convenience;
# to do this, we reverse on store if BE is requested, and always reverse on load since SimMemory will reverse again if LE is requested
class FractionalMemory(SimMemory):
    FRACS_NAME = "_fracs"

    def __init__(self, memory_id='', memory=None, fractions_memory=None, endness=None, handled_objs=None):
        SimMemory.__init__(self, endness=endness, abstract_backer=None, stack_region_map=None, generic_region_map=None)
        self.id = memory_id # magic! needs to be set for SimMemory to work
        self.memory = memory or SegmentedMemory(memory_id)
        self.fractions_memory = fractions_memory or SegmentedMemory(memory_id)
        self.handled_objs = handled_objs or HashDict()

    def set_state(self, state):
        SimMemory.set_state(self, state)
        self.memory.set_state(state)
        self.fractions_memory.set_state(state)

    @SimStatePlugin.memo
    def copy(self, memo):
        return FractionalMemory(memory_id=self.id, memory=self.memory.copy(memo), fractions_memory=self.fractions_memory.copy(memo), endness=self.endness, handled_objs=copy.deepcopy(self.handled_objs))

    def merge(self, others, merge_conditions, common_ancestor=None):
        if any(o.id != self.id for o in others) or any(o.endness != self.endness for o in others):
            raise SymbexException("Merging FractionalMemory instances with different IDs or endnesses is not supported")

        self.memory.merge([o.memory for o in others], merge_conditions, common_ancestor=common_ancestor.memory if common_ancestor is not None else None)
        self.fractions_memory.merge([o.fractions_memory for o in others], merge_conditions, common_ancestor=common_ancestor.fractions_memory if common_ancestor is not None else None)
        # TODO deal with handled_objs explicitly here? even if it's just a "if they're not equal, fail" check...
        return True


    # This method handles endness on its own
    def _store(self, request): # request is MemoryStoreRequest; has addr, data=None, size=None, condition=None, endness + "completed" must be set to True
        endness = self.endness if request.endness is None else request.endness
        if endness == archinfo.Endness.BE:
            request.data = request.data.reversed
        request.endness = archinfo.Endness.BE

        (base, index, offset) = self.memory.base_index_offset(request.addr)
        if base in self.handled_objs:
            self.handled_objs[base][1](self.state, base, index, offset, request.data)
            return

        facts = self.state.metadata.get(Facts, base)
        fraction = self.fractions_memory.load(facts.fractions + index, 1)
        if utils.can_be_true(self.state.solver, fraction != 100):
            raise SymbexException("Attempt to store without definitely owning the object at addr " + str(request.addr) + " ; fraction is " + str(fraction) + " ; constraints are " + str(self.state.solver.constraints) + " ; e.g. could be " + str(self.state.solver.eval_upto(fraction, 10, cast_to=int)))

        self.memory._store(request)

    # This method only partly handles endness; SimMemory will reverse if (endness or self.endness) is LE
    def _load(self, addr, size, condition=None, fallback=None, inspect=True, events=True, ret_on_segv=False):
        (base, index, offset) = self.memory.base_index_offset(addr)
        if base in self.handled_objs:
            return (addr, self.handled_objs[base][0](self.state, base, index, offset).reversed, [])

        facts = self.state.metadata.get(Facts, base)
        fraction = self.fractions_memory.load(facts.fractions + index, 1)
        if utils.can_be_true(self.state.solver, fraction == 0):
            raise SymbexException("Attempt to load without definitely having access to the object at addr " + str(addr) + " ; fraction is " + str(fraction) + " ; constraints are " + str(self.state.solver.constraints) + " ; e.g. could be " + str(self.state.solver.eval_upto(fraction, 10, cast_to=int)))
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
        result = claripy.BVS(name + "_opaque", bitsizes.ptr)
        self.state.add_constraints(result != 0)
        self.state.path.ghost_record(lambda: RecordAllocateOpaque(name, result))
        return result

    def take(self, fraction, ptr, size): # fraction == None -> take all; size == None -> take all
        (base, index, offset) = self.memory.base_index_offset(ptr)
        if offset != 0:
            if size is None:
                offset = 0
            else:
                raise SymbexException("Cannot take at an offset")

        facts = self.state.metadata.get(Facts, base)
        if size is None:
            size = facts.size
        if utils.can_be_true(self.state.solver, facts.size != size):
            raise SymbexException("Can only take entire items ; you wanted " + str(size) + " but the item size is " + str(facts.size))

        current_fraction = self.fractions_memory.load(facts.fractions + index, 1)
        if fraction is None:
            fraction = current_fraction

        if utils.can_be_true(self.state.solver, current_fraction.ULT(fraction)):
            raise SymbexException("Cannot take " + str(fraction) + " ; there is only " + str(current_fraction))

        self.fractions_memory.store(facts.fractions + index, (current_fraction - fraction), size=1)
        return current_fraction

    def give(self, fraction, ptr, size):
        (base, index, offset) = self.memory.base_index_offset(ptr)
        if offset != 0:
            raise SymbexException("Cannot give at an offset")

        facts = self.state.metadata.get(Facts, base)
        if utils.can_be_true(self.state.solver, facts.size != size):
            raise SymbexException("Can only give entire items ; you wanted " + str(size) + " but the item size is " + str(facts.size))

        current_fraction = self.fractions_memory.load(facts.fractions + index, 1)
        if utils.can_be_true(self.state.solver, (current_fraction + fraction).UGT(100)):
            raise SymbexException("Cannot give " + str(fraction) + " ; there is already " + str(current_fraction))

        self.fractions_memory.store(facts.fractions + index, (current_fraction + fraction), size=1)

    # reader: (state, base, index, offset) -> value
    # writer: (state, base, index, offset, value) -> void
    def add_obj_handler(self, obj, size, reader, writer):
        self.memory.add_size(obj, size)
        self.handled_objs[obj] = (reader, writer)

    def get_obj_and_size_from_fracs_obj(self, fracs_obj):
        if FractionalMemory.FRACS_NAME not in str(fracs_obj):
            return (None, None)
        for (o, facts) in self.state.metadata.get_all(Facts):
            if facts.fractions is fracs_obj:
                return (o, facts.size)
        raise SymbexException("What are you doing?")

    def havoc(self, addr):
        self.memory.havoc(addr)
        # don't havoc fractions, the notion of fractions doesn't really make sense with userspace BPF anyway, which this is for