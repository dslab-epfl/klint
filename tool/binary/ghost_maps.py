# Standard/External libraries
import angr
from angr.state_plugins.plugin import SimStatePlugin
import claripy
import copy
import itertools
import os
import threading
import queue
from collections import namedtuple
from enum import Enum

# Us
from . import utils
from .exceptions import SymbexException
from .metadata import Metadata

# Helper function to make expressions clearer
def Implies(a, b):
    return ~a | b

# "length" is symbolic, and may be larger than len(items) if there are items that are not exactly known
# "invariants" is a list of conjunctions that represents unknown items: each is a lambda that takes (state, item) and returns a Boolean expression
# "items" contains exactly known items, which do not have to obey the invariants
MapMeta = namedtuple("MapMeta", ["name", "key_size", "value_size"]) # sizes are ints (not BVs!), in bits
MapItem = namedtuple("MapItem", ["key", "value", "present"])

class Map:
    # === Public API ===

    @staticmethod
    def new(state, key_size, value_size, name, length, invariants, _name_counter=[0]): # use a list for the counter as a byref equivalent
        def to_int(n, name):
            if isinstance(n, claripy.ast.base.Base) and n.symbolic:
                raise SymbexException(name + " cannot be symbolic")
            return state.solver.eval_one(n, cast_to=int)

        key_size = to_int(key_size, "key_size")
        value_size = to_int(value_size, "value_size")

        name = name + "_" + str(_name_counter[0])
        _name_counter[0] = _name_counter[0] + 1

        return Map(MapMeta(name, key_size, value_size), length, invariants, [])

    def length(self, from_present=True):
        if from_present or self._previous is None:
            return self._length
        return self._previous.length(from_present=False)

    def get(self, state, key, value=None, from_present=True):
        # Optimization: If the map is empty, the answer is always false
        if self.is_empty(from_present=from_present):
            return (claripy.BVS(self.meta.name + "_bad_value", self.meta.value_size), claripy.false)

        # Let V be a fresh symbolic value [or use the hint]
        if value is None or not value.symbolic:
            value = claripy.BVS(self.meta.name + "_value", self.meta.value_size)

        # Let P be a fresh symbolic presence bit
        present = claripy.BoolS(self.meta.name + "_present")

        known_items = self.known_items(from_present=from_present)
        new_known_item = MapItem(key, value, present)

        # If the map contains an item (K', V', P') such that K' = K, then return (V', P') [so that invariants can reference each other]
        matching_item = utils.get_exact_match(state.solver, key, known_items, selector=lambda i: i.key)
        if matching_item is not None:
            return (matching_item.value, matching_item.present)

        # Let UK be And(K != K') for each key K' in the map's known items [in the present or the past]
        unknown = claripy.And(*[key != i.key for i in known_items])

        # MUTATE the map's known items by adding (K, V, P) [in the present or the past]
        self.add_item(new_known_item, from_present=from_present)

        utils.add_constraints_and_check_sat(state,
            # Add K = K' => (V = V' and P = P') to the path constraint for each item (K', V', P') in the map [from the present or the past],
            *[Implies(key == i.key, (value == i.value) & (present == i.present)) for i in known_items],
            # Add UK => invariant(M)(K', V', P') to the path constraint [invariant in the present or the past]
            Implies(unknown, self.invariant(from_present=from_present)(state, new_known_item)),
            # Add L <= length(M) [in the present or the past]
            self.known_length(from_present=from_present) <= self.length(from_present=from_present)
        )

        # Return (V, P)
        return (value, present)

    def set(self, state, key, value):
        # Let P be get(M, K) != None
        (_, present) = self.get(state, key)

        # Return a new map with:
        #   ITE(P, 0, 1) added to the map length.
        #   Each known item (K', V', P') updated to (K', ITE(K = K', V', V), ITE(K = K', true, P'))
        #   (K, V, true) added to the known items
        return self.with_items_layer(
            items=[MapItem(key, value, claripy.true)],
            length_change=claripy.If(present, claripy.BVV(0, self.length().size()), claripy.BVV(1, self.length().size())),
            filter=lambda i: not i.key.structurally_match(key), # Optimization: Filter out known-obsolete keys already
            map=lambda i: MapItem(i.key, claripy.If(i.key == key, value, i.value), claripy.If(i.key == key, claripy.true, i.present))
        )

    def remove(self, state, key):
        # Let P be get(M, K) != None
        (_, present) = self.get(state, key)

        # Create a fresh symbolic value V.
        value = claripy.BVS(self.meta.name + "_bad_value", self.meta.value_size)

        # Return a new map with:
        #   ITE(P, -1, 0) added to the map length
        #   Each known item (K', V', P') updated to (K', ITE(K = K', V, V'), ITE(K = K', false, P'))
        #   (K, V, false) added to the known items
        return self.with_items_layer(
            items=[MapItem(key, value, claripy.false)],
            length_change=claripy.If(present, claripy.BVV(-1, self.length().size()), claripy.BVV(0, self.length().size())),
            filter=lambda i: not i.key.structurally_match(key), # Optimization: Filter out known-obsolete keys already
            map=lambda i: MapItem(i.key, claripy.If(i.key == key, value, i.value), claripy.If(i.key == key, claripy.false, i.present))
        )

    def forall(self, state, pred, _known_only=False):
        # Optimization: If the map is empty, the answer is always true
        if self.is_empty():
            return claripy.true

        # Let K' be a fresh symbolic key and V' a fresh symbolic value
        test_key = claripy.BVS(self.meta.name + "_test_key", self.meta.key_size)
        test_value = claripy.BVS(self.meta.name + "_test_value", self.meta.value_size)

        # Let L be the number of known items whose presence bit is set
        # Let F = ((P1 => pred(K1, V1)) and (P2 => pred(K2, V2)) and (...) and ((L < length(M)) => (invariant(M)(K', V', true) => pred(K', V'))))
        # Optimization: No need to even call the invariant if we're sure all items are known
        result = claripy.And(*[Implies(i.present, pred(i.key, i.value)) for i in self.known_items()])
        if not _known_only and utils.can_be_false(state.solver, self.known_length() == self.length()):
            result &= Implies(
                          self.known_length() < self.length(),
                          Implies(
                              self.invariant()(state, MapItem(test_key, test_value, claripy.true)),
                              pred(test_key, test_value)
                          )
                      )

        # Optimization: No need to change the invariant if it's definitely not useful
        if utils.definitely_true(state.solver, result):
            return claripy.true
        if utils.definitely_false(state.solver, result):
            return claripy.false

        # MUTATE the map's invariant by adding F => (P => pred(K, V))
        self.add_invariant(lambda st, i: Implies(result, Implies(i.present, pred(i.key, i.value))))

        # Return F
        return result


    # === Private API, also used by invariant inference ===

    def __init__(self, meta, length, invariants, known_items, _previous=None, _filter=None, _map=None):
        self.meta = meta
        self._length = length
        self._invariants = invariants
        self._known_items = known_items
        self._previous = _previous
        self._filter = _filter or (lambda i: True)
        self._map = _map or (lambda i: i)

    def invariant_conjunctions(self, from_present=True):
        if from_present or self._previous is None:
            return self._invariants
        return self._invariants + self._previous.invariant_conjunctions(from_present=False)

    def invariant(self, from_present=True):
        return lambda st, i, invs=self.invariant_conjunctions(from_present): claripy.And(*[inv(st, i) for inv in invs])

    def add_invariant(self, conjunction):
        self._invariants.append(conjunction)

    def with_added_invariant(self, conjunction):
        result = self.__copy__()
        result._invariants.append(conjunction)
        return result

    def with_invariant_conjunctions(self, new_invariant_conjunctions):
        result = self.__copy__()
        result._invariants = new_invariant_conjunctions
        return result

    def known_items(self, from_present=True, _next=None):
        if from_present:
            return self._known_items + list(map(self._map, filter(self._filter, () if self._previous is None else self._previous.known_items())))

        result = self._known_items + list(map(self._map, filter(self._filter, _next or ())))
        if self._previous is None:
            return result
        return self._previous.known_items(from_present=False, _next=result)

    def add_item(self, item, from_present=True):
        if from_present or self._previous is None:
            self._known_items.append(item)
        else:
            self._previous.add_item(item, from_present=False)

    def with_items_layer(self, items, length_change, filter, map):
        return Map(
            self.meta,
            self._length + length_change,
            self._invariants.copy(),
            items,
            _previous=self,
            _filter=filter,
            _map=map
        )

    def flatten(self):
        return Map(
            self.meta,
            self._length,
            self._invariants,
            list(self.known_items())
        )

    def with_length(self, new_length):
        result = self.__copy__()
        result._length = new_length
        return result

    def is_empty(self, from_present=True):
        l = self.length(from_present=from_present)
        return l.structurally_match(claripy.BVV(0, l.size()))

    def known_length(self, from_present=True):
        l = self.length(from_present=from_present)
        known_len = claripy.BVV(0, l.size())
        known_keys = []
        for item in self.known_items(from_present=from_present):
            key_is_new = claripy.And(*[item.key != k for k in known_keys])
            known_keys.append(item.key)
            known_len = known_len + claripy.If(key_is_new & item.present, claripy.BVV(1, l.size()), claripy.BVV(0, l.size()))
        return known_len

    def __copy__(self):
        return self.__deepcopy__({})

    def __deepcopy__(self, memo):
        result = Map(self.meta, self._length, copy.deepcopy(self._invariants, memo), copy.deepcopy(self._known_items, memo), copy.deepcopy(self._previous, memo), self._filter, self._map)
        memo[id(self)] = result
        return result

    def __repr__(self):
        return "[Map: " + self.meta.name + "]"

    def _asdict(self): # pretend we are a namedtuple so functions that expect one will work (e.g. utils.structural_eq)
        return {'meta': self.meta, '_length': self._length, '_invariants': self._invariants, '_known_items': self._known_items, '_previous': self._previous, '_filter': self._filter, '_map': self._map}

class GhostMaps(SimStatePlugin):
    # === Public API ===

    def new(self, key_size, value_size, name="map", length_size=64):
        obj = self.state.memory.allocate_opaque(name)
        self.state.metadata.set(obj, Map.new(self.state, key_size, value_size, name, claripy.BVV(0, length_size), [lambda st, i: ~i.present]))
        return obj

    def new_array(self, key_size, value_size, length, name="map"):
        obj = self.state.memory.allocate_opaque(name)
        self.state.metadata.set(obj, Map.new(self.state, key_size, value_size, name, length, [lambda st, i: (i.key < length) == i.present]))
        return obj

    def length(self, obj):
        return self[obj].length()

    def key_size(self, obj):
        return self[obj].meta.key_size

    def value_size(self, obj):
        return self[obj].meta.value_size

    def get(self, obj, key, value=None, from_present=True):
        map = self[obj]
        LOG(self.state, "GET " + map.meta.name + " " + ("present" if from_present else "past") + (" key: " + str(key)) + ((" value: " + str(value)) if value is not None else "") + \
                        " (" + str(len(list(map.known_items(from_present=from_present)))) + " items, " + str(len(self.state.solver.constraints)) + " constraints)")
        result = map.get(self.state, key, value=value, from_present=from_present)
        LOGEND(self.state)
        return result

    def set(self, obj, key, value):
        self.state.metadata.set(obj, self[obj].set(self.state, key, value), override=True)

    def remove(self, obj, key):
        self.state.metadata.set(obj, self[obj].remove(self.state, key), override=True)

    def forall(self, obj, pred, _known_only=False):
        map = self[obj]
        LOG(self.state, "forall " + map.meta.name + " ( " + str(len(self.state.solver.constraints)) + " constraints)")
        result = map.forall(self.state, pred, _known_only=_known_only)
        LOGEND(self.state)
        return result


    # === Private API, including for invariant inference ===

    def __init__(self):
        SimStatePlugin.__init__(self)
        Metadata.set_merge_funcs(Map, maps_merge_across, maps_merge_one)

    @SimStatePlugin.memo
    def copy(self, memo):
        return GhostMaps()

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True

    def __getitem__(self, obj):
        # Shortcut
        return self.state.metadata.get(Map, obj)


class ResultType(Enum):
    LENGTH_LTE = 0
    LENGTH_VAR = 1
    CROSS_VAL = 2
    CROSS_KEY = 3

    def is_cross_result(self):
        return self == ResultType.CROSS_VAL or self == ResultType.CROSS_KEY

    def __str__(self):
        if self == ResultType.LENGTH_LTE:
            return "LENGTH_LTE"
        elif self == ResultType.LENGTH_VAR:
            return "LENGTH_VAR"
        elif self == ResultType.CROSS_VAL:
            return "CROSS_VAL"
        elif self == ResultType.CROSS_KEY:
            return "CROSS_KEY"
        raise ValueError("Unknown ResultType")


# Quick and dirty logging...
LOG_levels = {}
def LOG(state, text):
    if id(state) in LOG_levels:
        level = LOG_levels[id(state)]
    else:
        level = 1
    LOG_levels[id(state)] = level + 1
    #print(level, "  " * level, text)
def LOGEND(state):
    LOG_levels[id(state)] = LOG_levels[id(state)] - 1
    
# state args have a leading _ to ensure toe functions run concurrently don't accidentally touch them
def maps_merge_across(_states_to_merge, objs, _ancestor_state, _cache={}):
    print(f"Cross-merge of maps starting. State count: {len(_states_to_merge)}")

    _states = _states_to_merge + [_ancestor_state]
    first_time = len(_cache) == 0
    get_key = lambda i: i.key
    get_value = lambda i: i.value
    ancestor_variables = _ancestor_state.solver.variables(claripy.And(*_ancestor_state.solver.constraints))

    def init_cache(objs):
        for (o1, o2) in itertools.permutations(objs, 2):
            if o1 not in _cache:
                _cache[o1] = {}
            if o2 not in _cache[o1]:
                _cache[o1][o2] = {k: (False, None) for k in ["k", "p", "v"]}

    def get_cached(o1, o2, op):
        return _cache[o1][o2][op]

    def set_cached(o1, o2, op, val):
        _cache[o1][o2][op] = (True, val)

    # helper function to get only the items that are definitely in the map associated with the given obj in the given state
    def filter_present(state, obj):
        present_items = set()
        for i in state.maps[obj].known_items():
            if utils.definitely_true(state.solver, claripy.And(i.present, *[i.key != pi.key for pi in present_items])):
                present_items.add(i)
        return present_items

    # helper function to find FK or FV
    def find_f(states, o1, o2, sel1, sel2, candidate_finders):
        # Returns False iff the candidate function cannot match each element in items1 with an element of items2 
        def is_candidate_valid(items1, items2, candidate_func):
            for it1 in items1:
                # @TODO Here we could loop over all items in items2 at each iteration, to maximize our chance of
                # satisfying the candidate. Of course that would increase execution-time...
                if not utils.definitely_true(state.solver, sel2(items2.pop()) == candidate_func(state, it1, True)):
                    return False
            return True
        
        candidate_func = None
        
        for state in states:
            items1 = filter_present(state, o1)
            items2 = filter_present(state, o2)
            if len(items1) == 0:
                # If there are no items in 1 it's fine but doesn't give us info either
                continue
            elif len(items1) > len(items2):
                # Pigeonhole: there must be an item in 1 that does not match one in 2
                return None
            elif len(items1) < len(items2):
                # Lazyness: implementing backtracking in case a guess fails is hard :p
                raise SymbexException("backtracking not implemented yet")

            if candidate_func is None:
                # No candidate yet (1st iteration), try and find one
                it1 = items1.pop()
                for it2 in items2:
                    for finder in candidate_finders: # Use the finders
                        candidate_func = finder(state, o1, o2, sel1, sel2, it1, it2)
                        if candidate_func is not None:
                            items2.remove(it2)
                            if not is_candidate_valid(items1, items2, candidate_func):
                                return None
                            # @TODO If is_candidate_valid returns false we could technically re-add it2 to items2 and try again
                            # with another item
                            break
                    if candidate_func is not None:
                        break
                else:
                    # We couldn't find a candidate function
                    return None
            elif is_candidate_valid(items1, items2, candidate_func):
                # Candidate looks OK, keep going
                continue
            else:
                # Candidate failed :(
                return None
            
        # Our candidate has survived all states!
        return candidate_func

    # Helper function to find FP
    def find_f_constants(states, o, sel):
        constants = set([utils.get_if_constant(state.solver, sel(i)) for state in states for i in filter_present(state, o)])
        return [lambda i: claripy.true] + [lambda i, c=c: sel(i) == claripy.BVV(c, sel(i).size()) for c in constants if c is not None]

    def candidate_finder_1(state, o1, o2, sel1, sel2, it1, it2):
        # The ugliest one first: if o1 is a "fractions" obj, check if the corresponding value in the corresponding obj is equal to x2.reversed
        x2 = sel2(it2)
        if sel1 is get_key:
            # note that orig_size is in bytes, but x2.size() is in bits!
            orig_o1, orig_size = state.memory.get_obj_and_size_from_fracs_obj(o1)
            if orig_o1 is not None and orig_o1 is not o2 and utils.definitely_true(state.solver, orig_size * 8 == x2.size()):
                (orig_x1v, orig_x1p) = state.maps.get(orig_o1, it1.key)
                if utils.definitely_true(state.solver, orig_x1p & (orig_x1v == x2.reversed)):
                    return lambda st, it, from_present, orig_o1=orig_o1: st.maps.get(orig_o1, it.key, from_present=from_present)[0].reversed
        return None

    def candidate_finder_2(state, o1, o2, sel1, sel2, it1, it2):
        x1 = sel1(it1)
        x2 = sel2(it2)
        if x1.size() == x2.size():
            if utils.definitely_true(state.solver, x1 == x2):
                # Identity is a possible function
                return lambda st, it, _: sel1(it)

            fake = claripy.BVS("fake", x1.size())
            if not x2.replace(x1, fake).structurally_match(x2):
                # Replacement is a possible function
                return lambda st, it, _, x1=x1, x2=x2: x2.replace(x1, sel1(it))

            # a few special cases on the concept of finding a function and its inverse
            # if x1 is "(0..x)" and x2 contains "x"
            if x1.op == "Concat" and \
            len(x1.args) == 2 and \
            x1.args[0].structurally_match(claripy.BVV(0, x1.args[0].size())):
                fake = claripy.BVS("fake", x1.args[1].size())
                if not x2.replace(x1.args[1], fake).structurally_match(x2):
                    return lambda st, it, _, x1=x1, x2=x2: x2.replace(x1.args[1], claripy.Extract(x1.args[1].size() - 1, 0, sel1(it)))
                    
            # if x1 is "(x..0) + n" where n is known from the ancestor and x2 contains "x"
            if x1.op == "__add__" and \
            len(x1.args) == 2 and \
            state.solver.variables(x1.args[1]).issubset(ancestor_variables) and \
            x1.args[0].op == "Concat" and \
            len(x1.args[0].args) == 2 and \
            x1.args[0].args[1].structurally_match(claripy.BVV(0, x1.args[0].args[1].size())):
                fake = claripy.BVS("fake", x1.args[0].args[0].size())
                if not x2.replace(x1.args[0].args[0], fake).structurally_match(x2):
                    return lambda st, it, _, x1=x1, x2=x2: x2.replace(x1.args[0].args[0], claripy.Extract(x1.size() - 1, x1.args[0].args[1].size(), sel1(it) - x1.args[1]))
                if utils.definitely_true(state.solver, x2 == x1.args[0].args[0].zero_extend(x1.size() - x1.args[0].args[0].size())):
                    return lambda st, it, _, x1=x1: claripy.Extract(x1.size() - 1, x1.args[0].args[1].size(), sel1(it) - x1.args[1]).zero_extend(x1.args[0].args[1].size())
        return None

    def candidate_finder_3(state, o1, o2, sel1, sel2, it1, it2):
        x2 = sel2(it2)
        if sel2 is get_value:
            const = utils.get_if_constant(state.solver, x2)
            if const is not None:
                # A constant is a possible function
                return lambda st, it, _, const=const, sz=x2.size(): claripy.BVV(const, sz)
        return None

    def thread_main(ancestor_state, orig_states):
        while True:
            try:
                (o1, o2) = remaining_work.get(block=False)
            except queue.Empty:
                return

            # Step 2: Length relationships.
            # For each pair of maps (M1, M2),
            #   if length(M1) <= length(M2) across all states,
            #   then assume this holds in the merged state
            if all(utils.definitely_true(st.solver, st.maps.length(o1) <= st.maps.length(o2)) for st in orig_states):
                results.put((ResultType.LENGTH_LTE, [o1, o2], lambda st, ms: st.add_constraints(ms[0].length() <= ms[1].length())))

            # Step 2: Map relationships.
            # For each pair of maps (M1, M2),
            #  if there exist functions FP, FK such that in all states, forall(M1, (K,V): FP(K,V) => get(M2, FK(K, V)) == (_, true)),
            #  then assume this is an invariant of M1 in the merged state.
            # Additionally,
            #  if there exists a function FV such that in all states, forall(M1, (K,V): FP(K,V) => get(M2, FK(K, V)) == (FV(K, V), true)),
            #  then assume this is an invariant of M1 in the merged state.
            # We use maps directly to refer to the map state as it was in the ancestor, not during execution;
            # otherwise, get(M1, k) after remove(M2, k) might add has(M2, k) to the constraints, which is obviously false
            
            # Try to find a FK
            (fk_is_cached, fk) = get_cached(o1, o2, "k")
            if not fk_is_cached:
                fk = find_f(orig_states, o1, o2, get_key, get_key, candidate_finders) \
                  or find_f(orig_states, o1, o2, get_value, get_key, candidate_finders)
                to_cache.put([o1, o2, "k", fk])
            if not fk:
                # No point in continuing if we couldn't find a FK
                continue

            # Try to find a few FPs
            (fps_is_cached, fps) = get_cached(o1, o2, "p")
            if not fps_is_cached:
                fps = find_f_constants(orig_states, o1, get_value)

            for fp in fps:
                states = [s.copy() for s in orig_states]
                if all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v, st=st, o2=o2, fp=fp, fk=fk: Implies(fp(MapItem(k, v, None)), st.maps.get(o2, fk(st, MapItem(k, v, None), True))[1]), _known_only=not first_time)) for st in states):
                    to_cache.put([o1, o2, "p", [fp]]) # only put the working one, don't have us try a pointless one next time
                    
                    # Logging
                    log_item = MapItem(claripy.BVS("K", ancestor_state.maps.key_size(o1)), claripy.BVS("V", ancestor_state.maps.value_size(o1)), None)
                    log_text = f"Inferred: when {o1} contains (K,V), if {fp(log_item)} then {o2} contains {fk(ancestor_state, log_item, True)}"
                    
                    # Try to find a FV
                    (fv_is_cached, fv) = get_cached(o1, o2, "v")
                    if not fv_is_cached:
                        fv = find_f(orig_states, o1, o2, get_key, get_value, candidate_finders) \
                          or find_f(orig_states, o1, o2, get_value, get_value, candidate_finders)
                        to_cache.put([o1, o2, "v", fv])
                    
                    states = [s.copy() for s in orig_states]
                    if fv and all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v, st=st, o2=o2, fp=fp, fk=fk, fv=fv: Implies(fp(MapItem(k, v, None)), st.maps.get(o2, fk(st, MapItem(k, v, None), True))[0] == fv(st, MapItem(k, v, None), True)), _known_only=not first_time)) for st in states):
                        log_text += f"\n\tin addition, the value is {fv(ancestor_state, log_item, True)}"
                        # Python doesn't have multiline lambdas :/
                        def cross_val_inv(st, i, o2, fp, fk, fv):
                            fvres = fv(st, i, False)
                            (o2val, o2pres) = st.maps.get(o2, fk(st, i, False), value=fvres, from_present=False)
                            return Implies(i.present, Implies(fp(i), o2pres & (o2val == fvres)))
                        results.put((ResultType.CROSS_VAL, [o1, o2], lambda state, maps, o2=o2, fp=fp, fk=fk, fv=fv: [maps[0].with_added_invariant(lambda st, i: cross_val_inv(st, i, o2, fp, fk, fv)), maps[1]]))
                    else:
                        cross_key_inv = lambda st, i, o2, fp, fk: Implies(i.present, Implies(fp(i), st.maps.get(o2, fk(st, i, False), from_present=False)[1]))
                        results.put((ResultType.CROSS_KEY, [o1, o2], lambda state, maps, o2=o2, fp=fp, fk=fk: [maps[0].with_added_invariant(lambda st, i: cross_key_inv(st, i, o2, fp, fk)), maps[1]]))
                   
                    print(log_text) # print it at once to avoid interleavings from threads
                    break # this might make us miss some stuff in theory? but that's sound; and in practice it doesn't
            else:
                to_cache.put([o1, o2, "p", []])

    # Optimization: Ignore maps that have not changed at all, e.g. those that are de facto readonly after initialization
    objs = [o for o in objs if any(not utils.structural_eq(_ancestor_state.maps[o], st.maps[o]) for st in _states)]

    # Initialize the cache for fast read/write acces during invariant inference
    init_cache(objs)

    # List all candidate finders used by find_f
    candidate_finders = [candidate_finder_1, candidate_finder_2, candidate_finder_3]

    results = queue.Queue() # pairs: (ID, maps, lambda states, maps: returns None for no changes or maps to overwrite them)
    to_cache = queue.Queue() # set_cached(...) will be called with all elements in there

    # Invariant inference algorithm: if some property P holds in all states to merge and the ancestor state, optimistically assume it is part of the invariant
    for o in objs:
        # Step 1: Length variation.
        # If the length may have changed in any state from the one in the ancestor state,
        # replace the length with a fresh symbol
        ancestor_length = _ancestor_state.maps.length(o)
        for state in _states_to_merge:
            if utils.can_be_false(state.solver, state.maps.length(o) == ancestor_length):
                print("Length of map", o, " was changed; making it symbolic")
                results.put((ResultType.LENGTH_VAR, [o], lambda st, ms: [ms[0].with_length(claripy.BVS("map_length", ms[0].length().size()))]))
                break

    remaining_work = queue.Queue()
    for (o1, o2) in itertools.permutations(objs, 2):
        remaining_work.put((o1, o2))
    
    # Multithreading disabled because it causes weird errors (maybe we're configuring angr wrong; we end up with a claripy mixin shared between threads)
    # and even segfaults (which look like z3 is accessed concurrently when it shouldn't be)
    thread_main(_ancestor_state.copy(), [s.copy() for s in _states])
    """threads = []
    for n in range(os.cpu_count()): # os.sched_getaffinity(0) would be better (get the CPUs we might be restricted to) but is not available on Win and OSX
        t = threading.Thread(group=None, target=thread_main, name=None, args=[_ancestor_state.copy(), [s.copy() for s in _states]], kwargs=None, daemon=False)
        t.start()
        threads.append(t)
    for thread in threads:
        thread.join()"""

    # Convert results queue into lists (split cross results from length results)
    cross_results = []
    length_results = []
    while not results.empty():
        res = results.get(block=False)
        if res[0].is_cross_result():
            cross_results.append(res)
        else:
            length_results.append(res)

    # Fill cache
    while not to_cache.empty():
        set_cached(*(to_cache.get(block=False)))

    # Ensure we don't pollute states through the next check
    _orig_states = [s.copy() for s in _states]

    # Optimization: Remove redundant inferences.
    # That is, for pairs (M1, M2) of maps whose keys are the same in all states and which lead to the same number of inferences,
    # remove all map relationships of the form (M2, M3) if (M1, M3) exists, as well as those of the form (M3, M2) if (M3, M1) exists.
    # This is a conservative algorithm; a better version eliminating more things would need to keep track of whether relationships are lossy,
    # to avoid eliminating a lossless relationship in favor of a lossy one, and create a proper graph instead of relying on pairs.
    for (o1, o2) in itertools.combinations(objs, 2):
        if _ancestor_state.maps.key_size(o1) == _ancestor_state.maps.key_size(o2) and \
            sum(1 for r in cross_results if r[1][0] is o1) == sum(1 for r in cross_results if r[1][0] is o2):
            states = [s.copy() for s in _orig_states]
            if all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v, st=st: st.maps.get(o2, k)[1])) for st in states):
                to_remove  = [r for r in cross_results
                                if r[1][1] is o2
                                and any(True for r2 in cross_results
                                             if  r2[1][1] is o1
                                             and r2[1][0] is r[1][0])]

                to_remove += [r for r in cross_results
                                if r[1][0] is o2
                                and any(True for r2 in cross_results
                                             if r2[1][0] is o1
                                             and r2[1][1] is r[1][1])]

                for r in to_remove:
                    print(f"Discarding redundant inference {r[0]} between {r[1]}")
                # can't just use "not in" due to claripy's ==
                to_remove_ids = set(id(r) for r in to_remove)
                cross_results = [r for r in cross_results if id(r) not in to_remove_ids]

    return cross_results + length_results

def maps_merge_one(states_to_merge, obj, ancestor_state):
    print("Merging map", obj)
    # helper function to find constraints that hold on an expression in a state
    ancestor_variables = ancestor_state.solver.variables(claripy.And(*ancestor_state.solver.constraints))
    def find_constraints(state, expr):
        # If the expression is constant or constrained to be, return that
        const = utils.get_if_constant(state.solver, expr)
        if const is not None:
            return [expr == const]
        # Otherwise, find constraints that contain the expression, but ignore those that also contain variables not in the ancestor
        # This might miss stuff due to transitive constraints,
        # but it's sound since having overly lax invariants can only over-approximate
        fake = claripy.BVS("fake", expr.size())
        expr_vars = state.solver.variables(expr)
        results = []
        for constr in state.solver.constraints:
            constr_vars = state.solver.variables(constr)
            if not constr.replace(expr, fake).structurally_match(constr) and constr_vars.difference(expr_vars).issubset(ancestor_variables):
                results.append(constr)
        return results

    # Optimization: Do not even consider maps that have not changed at all, e.g. those that are de facto readonly after initialization
    if all(utils.structural_eq(ancestor_state.maps[obj], st.maps[obj]) for st in states_to_merge):
        return (ancestor_state.maps[obj], False)

    flattened_states = [s.copy() for s in states_to_merge]
    for s in flattened_states:
        for (o, m) in s.metadata.get_all(Map):
            s.metadata.set(o, m.flatten(), override=True)

    # Oblivion algorithm: "forget" known items by integrating them into the unknown items invariant
    # For each conjunction in the unknown items invariant,
    # for each known item in any state,
    #  if the conjunction may not hold on that item assuming the item is present,
    #  find constraints that do hold and add them as a disjunction to the conjunction.
    invariant_conjs = []
    changed = False
    for conjunction in ancestor_state.maps[obj].invariant_conjunctions():
        for state in flattened_states:
            for item in state.maps[obj].known_items():
                conj = conjunction(state, item)
                if utils.definitely_false(state.solver, Implies(item.present, conj)):
                    changed = True
                    constraints = claripy.And(*find_constraints(state, item.key), *find_constraints(state, item.value))
                    print("Item", item, "in map", obj, "does not comply with invariant conjunction", conj, "; adding disjunction", constraints)
                    conjunction = lambda st, i, oldc=conjunction, oldi=item, cs=constraints: \
                                  oldc(st, i) | cs.replace(oldi.key, i.key).replace(oldi.value, i.value)
        invariant_conjs.append(conjunction)

    return (ancestor_state.maps[obj].flatten().with_invariant_conjunctions(invariant_conjs), changed)
