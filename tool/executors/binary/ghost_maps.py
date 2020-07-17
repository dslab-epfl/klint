import angr
from angr.state_plugins.plugin import SimStatePlugin
import claripy
from executors.binary.metadata import Metadata
import executors.binary.utils as utils
from collections import namedtuple
import copy
import itertools

# note: we use size-1 bitvectors instead of bools cause they sometimes behave weirdly in angr..
# e.g. sometimes (p and not(p)) is true :/
# TODO https://github.com/angr/angr/issues/2237 this has been fixed so maybe go back? or double-check their simplifications first?

# "length" is symbolic, and may be larger than len(items) if there are items that are not exactly known
# "invariants" is a list of conjunctions that represents unknown items: each is a lambda that takes (state, item) and returns a Boolean expression
# "items" contains exactly known items, which do not have to obey the invariants
MapMeta = namedtuple("MapMeta", ["name", "key_size", "value_size"]) # sizes are ints (not BVs!), in bits
MapItem = namedtuple("MapItem", ["key", "value", "present"])

class Map:
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
        return itertools.chain(self._invariants, self._previous.invariant_conjunctions(from_present=False))

    def invariant(self, from_present=True):
        return lambda st, i, invs=self.invariant_conjunctions(from_present): claripy.And(*[inv(st, i) for inv in invs])

    def add_invariant(self, conjunction):
        self._invariants.append(conjunction)

    def with_added_invariant(self, conjunction):
        result = self.__copy__()
        result._invariants.append(conjunction)
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

    def flatten(self, new_length, new_invariant_conjunctions):
        return Map(
            self.meta,
            new_length,
            new_invariant_conjunctions,
            list(self.known_items())
        )

    def length(self, from_present=True):
        if from_present or self._previous is None:
            return self._length
        return self._previous.length(from_present=False)

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
            known_len = known_len + claripy.If(claripy.And(key_is_new, item.present == 1), claripy.BVV(1, l.size()), claripy.BVV(0, l.size()))
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


# Helper function to make expressions clearer
def Implies(a, b):
    return claripy.Or(claripy.Not(a), b)

LOG_levels = {}
def LOG(state, text):
    if id(state) in LOG_levels:
        level = LOG_levels[id(state)]
    else:
        level = 1
    LOG_levels[id(state)] = level + 1
    print(level, "  " * level, text)

def LOGEND(state):
    LOG_levels[id(state)] = LOG_levels[id(state)] - 1

class GhostMaps(SimStatePlugin):
    def __init__(self):
        SimStatePlugin.__init__(self)
        Metadata.set_merge_funcs(Map, maps_merge_across, maps_merge_one)

    def set_state(self, state):
        SimStatePlugin.set_state(self, state)

    @SimStatePlugin.memo
    def copy(self, memo):
        return GhostMaps()

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True


    # Implementation details used by other functions & invariant inference
    def __getitem__(self, obj):
        return self.state.metadata.get(Map, obj)

    # Implementation detail used in the new* functions
    def _new(self, key_size, value_size, name, length, invariants, _name_counter=[0]): # use a list for the counter as a byref equivalent
        def to_int(n, name):
            if isinstance(n, claripy.ast.base.Base) and n.symbolic:
                raise (name + " cannot be symbolic")
            return self.state.solver.eval_one(n, cast_to=int)

        key_size = to_int(key_size, "key_size")
        value_size = to_int(value_size, "value_size")

        name = name + "_" + str(_name_counter[0])
        _name_counter[0] = _name_counter[0] + 1

        obj = self.state.memory.allocate_opaque(name)
        self.state.metadata.set(obj, Map(MapMeta(name, key_size, value_size), length, invariants, []))
        return obj


    def new(self, key_size, value_size, name="map", length_size=64):
        return self._new(key_size, value_size, name, claripy.BVV(0, length_size), [lambda st, i: i.present == 0])

    def new_array(self, key_size, value_size, length, name="map"):
        return self._new(key_size, value_size, name, length, [lambda st, i: (i.key < length) == (i.present == 1)])


    def length(self, obj):
        # Returns the map's length, including both known and unknown items.
        return self[obj].length()
    

    def key_size(self, obj):
        # Public implementation detail due to Python's untyped nature
        return self[obj].meta.key_size

    def value_size(self, obj):
        # Public implementation detail due to Python's untyped nature
        return self[obj].meta.value_size


    def add(self, obj, key, value):
        # Requires the map to not contain K.
        # Adds (K, V, true) to the known items.
        # Increments the map length.

        if utils.can_be_true(self.state.solver, self.get(obj, key)[1]):
            raise "Cannot add a key that might already be there!"

        map = self[obj]

        # Optimization: Filter out known-obsolete keys already
        map = map.with_items_layer(
            items=[MapItem(key, value, claripy.BVV(1, 1))],
            length_change=1,
            filter=lambda i: not i.key.structurally_match(key),
            map=lambda i: MapItem(i.key, claripy.If(i.key == key, value, i.value), claripy.If(i.key == key, claripy.BVV(1, 1), i.present))
        )
        self.state.metadata.set(obj, map, override=True)


    def remove(self, obj, key):
        # Requires the map to contain K.
        # Updates known items (K', V', P') into (K', V', P' and K != K')
        # Adds (K, V, false) to the known items.
        # Decrements the map length.

        if utils.can_be_false(self.state.solver, self.get(obj, key)[1]):
            raise "Cannot remove a key that might not be there!"

        map = self[obj]

        # Optimization: Filter out known-obsolete keys already
        bad_value = claripy.BVS("map_bad_value", map.meta.value_size)
        map = map.with_items_layer(
            items=[MapItem(key, bad_value, claripy.BVV(0, 1))],
            length_change=-1,
            filter=lambda i: not i.key.structurally_match(key),
            map=lambda i, bad_value=bad_value: MapItem(i.key, claripy.If(i.key == key, bad_value, i.value), claripy.If(i.key == key, claripy.BVV(0, 1), i.present))
        )
        self.state.metadata.set(obj, map, override=True)


    def get(self, obj, key, value=None, from_present=True):
        # Let V be a fresh symbolic value
        # Let P be a fresh symbolic presence bit
        # Add K = K' => (V = V' and P = P') to the path constraint for each item (K', V', P') in the map [from the present or the past],
        # Let UNKNOWN be And(K != K') for each key K' in the map's known items [in the present or the past]
        # Add UNKNOWN => invariant(M)(K', V', P') to the path constraint [invariant in the present or the past]
        # Add (K, V, P) to the map's known items [in the present or the past]
        # Let L be the number of unique known keys in the map whose presence bit is set [in the present or the past] (including the newly-added item)
        # Add L <= length(M) [in the present or the past]
        # Return (V, P)

        map = self[obj]
        LOG(self.state, "GET " + map.meta.name + " " + ("present" if from_present else "past") + (" key: " + str(key)) + ((" value: " + str(value)) if value is not None else "") + " (" + str(len(list(map.known_items(from_present=from_present)))) + " items, " + str(len(self.state.solver.constraints)) + " constraints)")

        # Optimization: If the map is empty, the answer is always false
        if map.is_empty(from_present=from_present):
            LOGEND(self.state)
            return (claripy.BVS(map.meta.name + "_bad_value", map.meta.value_size), claripy.false)

        # TODO IMPORTANT NOT AN OPTIMIZATION
        # Optimization: If the key exactly matches an item, answer that
        # (note: having to use definitely_true makes it expensive, but it allows for simpler reasoning later)
        for item in map.known_items(from_present=from_present):
            if utils.definitely_true(self.state.solver, key == item.key):
                LOGEND(self.state)
                return (item.value, item.present == 1)

        if value is None or not value.symbolic:
            value = claripy.BVS(map.meta.name + "_value", map.meta.value_size)
        present = claripy.BVS(map.meta.name + "_present", 1)
        
        known_items = map.known_items(from_present=from_present)
        known_len = map.known_length(from_present=from_present)

        # MUTATE the map!
        map.add_item(MapItem(key, value, present), from_present=from_present)

        self.state.add_constraints(
            *[Implies(key == i.key, claripy.And(value == i.value, present == i.present)) for i in known_items],
            Implies(claripy.And(*[key != i.key for i in known_items]), map.invariant(from_present=from_present)(self.state, MapItem(key, value, present))),
            known_len <= map.length(from_present=from_present)
        )
        if not self.state.satisfiable():
            raise "Could not add constraints in ghost map get!?"

        LOGEND(self.state)
        return (value, present == 1)

    # TODO consider removing and using add + remove instead...
    def set(self, obj, key, value):
        # Requires the map to contain K.
        # Updates known items (K', V', P') into (K', ITE(K = K', V, V'), P' or K = K')
        # Adds (K, V, true) to the known items
        if utils.can_be_false(self.state.solver, self.get(obj, key)[1]):
            raise "Cannot set the value of a key that might not be there!"

        map = self[obj]

        # Optimization: Filter out known-obsolete keys already
        map = map.with_items_layer(
            items=[MapItem(key, value, claripy.BVV(1, 1))],
            length_change=0,
            filter=lambda i: not i.key.structurally_match(key),
            map=lambda i: MapItem(i.key, claripy.If(i.key == key, value, i.value), claripy.If(i.key == key, claripy.BVV(1, 1), i.present))
        )
        self.state.metadata.set(obj, map, override=True)


    def forall(self, obj, pred, _known_only=False):
        # Let L be the number of known items whose presence bit is set
        # Let K' be a fresh symbolic key and V' a fresh symbolic value
        # Let F = ((P1 => pred(K1, V1)) and (P2 => pred(K2, V2)) and (...) and ((L < length(M)) => (invariant(M)(K', V', true) => pred(K', V'))))
        # Add F => (P => pred(K, V)) to the map's invariant
        # Return F

        map = self[obj]
        LOG(self.state, "forall " + map.meta.name + " ( " + str(len(self.state.solver.constraints)) + " constraints)")

        # Optimization: If the map is empty, the answer is always true
        if map.is_empty():
            LOGEND(self.state)
            return claripy.true

        known_len = map.known_length()
        total_len = map.length()

        test_key = claripy.BVS(map.meta.name + "_test_key", map.meta.key_size)
        test_value = claripy.BVS(map.meta.name + "_test_value", map.meta.value_size)

        # Optimization: No need to even call the invariant if we're sure all items are known
        result = claripy.And(*[Implies(i.present == 1, pred(i.key, i.value)) for i in map.known_items()])
        if not _known_only and utils.can_be_false(self.state.solver, known_len == total_len):
            result = claripy.And(
                result,
                Implies(
                    known_len < total_len,
                    Implies(
                        map.invariant()(self.state, MapItem(test_key, test_value, claripy.BVV(1, 1))),
                        pred(test_key, test_value)
                    )
                )
            )

        # MUTATE the map!
        # Optimization: only if there's a chance it's useful, let's not needlessly complicate the invariant
        if utils.definitely_true(self.state.solver, result):
            LOGEND(self.state)
            return claripy.true
        if utils.definitely_false(self.state.solver, result):
            LOGEND(self.state)
            return claripy.false

        map.add_invariant(lambda st, i: Implies(result, Implies(i.present == 1, pred(i.key, i.value))))
        LOGEND(self.state)
        return result


def maps_merge_across(states_to_merge, objs, ancestor_state, _cache={}):
    print("Cross-merge of maps starting. State count:", len(states_to_merge))

    results = [] # pairs: (ID, maps, lambda states, maps: returns None for no changes or maps to overwrite them)
    states = states_to_merge + [ancestor_state]

    first_time = len(_cache) == 0

    def get_cached(o1, o2, op):
        key = str(o1) + str(o2) + op
        if key in _cache and _cache[key] != (): # () means negatively cached, see below
            return _cache[key]
        return None

    def set_cached(o1, o2, op, val):
        key = str(o1) + str(o2) + op
        if val is None:
            val = () # negative caching
        _cache[key] = val

    # helper function to get only the items that are definitely in the map associated with the given obj in the given state
    def filter_present(state, obj):
        known_keys = []
        present_items = []
        for i in state.maps[obj].known_items():
            if utils.definitely_true(state.solver, claripy.And(i.present == 1, *[i.key != pi.key for pi in present_items])):
                present_items.append(i)
        return present_items

    # helper function to find FK or FV
    ancestor_variables = ancestor_state.solver.variables(claripy.And(*ancestor_state.solver.constraints))
    def find_f(o1, o2, sel1, sel2, allow_constant=False):
        candidate_func = None
        for state in states:
            items1 = filter_present(state, o1)
            items2 = filter_present(state, o2)
            if len(items1) == 0:
                # If there are no items in 1 it's fine but doesn't give us info either
                continue
            if len(items1) > len(items2):
                # Pigeonhole: there must be an item in 1 that does not match one in 2
                return None
            if len(items1) != len(items2):
                # Lazyness: implementing backtracking in case a guess fails is hard :p
                raise "backtracking not implemented yet"
            for x1 in map(sel1, items1):
                found = False
                for it2 in items2:
                    x2 = sel2(it2)
                    if candidate_func is not None:
                        if utils.definitely_true(state.solver, x2 == candidate_func(x1)):
                            # All good, our candidate worked
                            found = True
                            items2.remove(it2)
                        # else: maybe next item?
                        break
                    if x1.size() == x2.size():
                        if utils.definitely_true(state.solver, x1 == x2):
                            # Identity is a possible function
                            candidate_func = lambda x: x
                            found = True
                            items2.remove(it2)
                            break
                        fake = claripy.BVS("fake", x1.size())
                        if not x2.replace(x1, fake).structurally_match(x2):
                            # Replacement is a possible function
                            candidate_func = lambda x, x1=x1, x2=x2: x2.replace(x1, x)
                            found = True
                            items2.remove(it2)
                            break
                        # a few special cases on the concept of finding a function and its inverse
                        # if x1 is "(0..x)" and x2 contains "x"
                        if x1.op == "Concat" and \
                           len(x1.args) == 2 and \
                           x1.args[0].structurally_match(claripy.BVV(0, x1.args[0].size())):
                            fake = claripy.BVS("fake", x1.args[1].size())
                            if not x2.replace(x1.args[1], fake).structurally_match(x2):
                                candidate_func = lambda x, x1=x1, x2=x2: x2.replace(x1.args[1], claripy.Extract(x1.args[1].size() - 1, 0, x))
                                found = True
                                items2.remove(it2)
                                break
                        # if x1 is "(x..0) + n" where n is known from the ancestor and x2 contains "x"
                        if x1.op == "__add__" and \
                           len(x1.args) == 2 and \
                           state.solver.variables(x1.args[1]).issubset(ancestor_variables) and \
                           x1.args[0].op == "Concat" and \
                           len(x1.args[0].args) == 2 and \
                           x1.args[0].args[1].structurally_match(claripy.BVV(0, x1.args[0].args[1].size())):
                            fake = claripy.BVS("fake", x1.args[0].args[0].size())
                            if not x2.replace(x1.args[0].args[0], fake).structurally_match(x2):
                                candidate_func = lambda x, x1=x1, x2=x2: x2.replace(x1.args[0].args[0], claripy.Extract(x1.size() - 1, x1.args[0].args[1].size(), x - x1.args[1]))
                                found = True
                                items2.remove(it2)
                                break
                            if utils.definitely_true(state.solver, x2 == x1.args[0].args[0].zero_extend(x1.size() - x1.args[0].args[0].size())):
                                candidate_func = lambda x, x1=x1: claripy.Extract(x1.size() - 1, x1.args[0].args[1].size(), x - x1.args[1]).zero_extend(x1.args[0].args[1].size())
                                found = True
                                items2.remove(it2)
                                break
                    if allow_constant:
                        const = utils.get_if_constant(state.solver, x2)
                        if const is not None:
                            # A constant is a possible function
                            candidate_func = lambda x, const=const, sz=x2.size(): claripy.BVV(const, sz)
                            found = True
                            items2.remove(it2)
                            break
                if not found:
                    # Found nothing in this state, give up
                    return None
        # Our candidate has survived all states!
        # Use sel1 here since we want the returned functions to take an item
        return lambda i: candidate_func(sel1(i))

    # Helper function to find FP
    def find_f_constants(o, sel):
        constants = set([utils.get_if_constant(state.solver, sel(i)) for state in states for i in filter_present(state, o)])
        return [lambda i: claripy.true] + [lambda i, c=c: sel(i) == claripy.BVV(c, sel(i).size()) for c in constants if c is not None]

    # Optimization: Ignore maps that have not changed at all, e.g. those that are de facto readonly after initialization
    objs = [o for o in objs if any(not utils.structural_eq(ancestor_state.maps[o], st.maps[o]) for st in states)]

    # Copy the states to avoid polluting the real ones for the next steps of inference
    orig_states = [s.copy() for s in states]

    # Invariant inference algorithm: if some property P holds in all states to merge and the ancestor state, optimistically assume it is part of the invariant
    for o1 in objs:
        for o2 in objs:
            if o1 is o2: continue

            # Step 1: Length.
            # For each pair of maps (M1, M2),
            #   if length(M1) <= length(M2) across all states,
            #   then assume this holds the merged state
            if all(utils.definitely_true(st.solver, st.maps.length(o1) <= st.maps.length(o2)) for st in states):
                results.append(("length", [o1, o2], lambda st, ms: st.add_constraints(ms[0].length() <= ms[1].length())))

            # Step 2: Cross-references.
            # For each pair of maps (M1, M2),
            #  if there exist functions FP, FK such that in all states, forall(M1, (K,V): FP(K,V) => get(M2, FK(K, V)) == (_, true)),
            #  then assume this is an invariant of M1 in the merged state.
            #  Additionally,
            #   if there exists a function FV such that in all states, forall(M1, (K,V): FP(K,V) => get(M2, FK(K, V)) == (FV(K, V), true)),
            #   then assume this is an invariant of M1 in the merged state.
            # TODO: a string ID is not really enough to guarantee the constraints are the same here...
            # We use maps directly to refer to the map state as it was in the ancestor, not during execution;
            # otherwise, get(M1, k) after remove(M2, k) might add has(M2, k) to the constraints, which is obviously false
            fk = get_cached(o1, o2, "k") \
              or find_f(o1, o2, lambda i: i.key, lambda i: i.key) \
              or find_f(o1, o2, lambda i: i.value, lambda i: i.key)
            set_cached(o1, o2, "k", fk)
            fps = get_cached(o1, o2, "p") \
               or find_f_constants(o1, lambda i: i.value)
            set_cached(o1, o2, "p", fps)
            for fp in fps:
                states = [s.copy() for s in orig_states]
                if fk and all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v, st=st, o2=o2, fp=fp, fk=fk: Implies(fp(MapItem(k, v, None)), st.maps.get(o2, fk(MapItem(k, v, None)))[1]), _known_only=not first_time)) for st in states):
                    log_item = MapItem(claripy.BVS("K", ancestor_state.maps.key_size(o1)), claripy.BVS("V", ancestor_state.maps.value_size(o1)), None)
                    print("Inferred: when", o1, "contains (K,V), if", fp(log_item), "then", o2, "contains", fk(log_item))
                    fv = get_cached(o1, o2, "v") \
                      or find_f(o1, o2, lambda i: i.key, lambda i: i.value, allow_constant=True) \
                      or find_f(o1, o2, lambda i: i.value, lambda i: i.value, allow_constant=True)
                    set_cached(o1, o2, "v", fv)
                    states = [s.copy() for s in orig_states]
                    if fv and all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v, st=st, o2=o2, fp=fp, fk=fk, fv=fv: Implies(fp(MapItem(k, v, None)), st.maps.get(o2, fk(MapItem(k, v, None)))[0] == fv(MapItem(k, v, None))), _known_only=not first_time)) for st in states):
                        print("          in addition, the value is", fv(log_item))
                        results.append(("cross-key", [o1, o2], lambda state, maps, o2=o2, fp=fp, fk=fk, fv=fv: [maps[0].with_added_invariant(lambda st, i, o2=o2, maps=maps, fp=fp, fk=fk, fv=fv: Implies(i.present == 1, Implies(fp(i), st.maps.get(o2, fk(i), value=fv(i), from_present=False)[1]))), maps[1]]))
                        results.append(("cross-val", [o1, o2], lambda state, maps, o2=o2, fp=fp, fk=fk, fv=fv: [maps[0].with_added_invariant(lambda st, i, o2=o2, maps=maps, fp=fp, fk=fk, fv=fv: Implies(i.present == 1, Implies(fp(i), st.maps.get(o2, fk(i), value=fv(i), from_present=False)[0] == fv(i)))), maps[1]]))
                    else:
                        results.append(("cross-key", [o1, o2], lambda state, maps, o2=o2, fp=fp, fk=fk: [maps[0].with_added_invariant(lambda st, i, o2=o2, maps=maps, fp=fp, fk=fk: Implies(i.present == 1, Implies(fp(i), st.maps.get(o2, fk(i), from_present=False)[1]))), maps[1]]))
                    break # this might make us miss some stuff in theory? but that's sound; and in practice it doesn't
    return results

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
        print("Map", obj, "has not changed at all")
        return ancestor_state.maps[obj]

    # Oblivion algorithm: "forget" known items by integrating them into the unknown items invariant
    invariant_conjs = []
    # Step 1: invariant.
    # For each conjunction in the unknown items invariant,
    # for each known item in any state,
    #  if the conjunction may not hold on that item assuming the item is present,
    #  find constraints that do hold and add them as a disjunction to the conjunction.
    for conjunction in ancestor_state.maps[obj].invariant_conjunctions():
        for state in states_to_merge:
            for item in state.maps[obj].known_items():
                if utils.can_be_true(state.solver, claripy.And(item.present == 1, claripy.Not(conjunction(state, item)))):
                    constraints = claripy.And(*find_constraints(state, item.key), *find_constraints(state, item.value))
                    print("Item", item, "in map", obj, "does not comply with one invariant conjunction; adding disjunction", constraints)
                    conjunction = lambda st, i, oldc=conjunction, oldi=item, cs=constraints: \
                                  claripy.Or(oldc(st, i), cs.replace(oldi.key, i.key).replace(oldi.value, i.value))
        invariant_conjs.append(conjunction)

    # Step 2: length.
    # If the length may have changed in any state from the one in the ancestor state,
    # replace the length with a fresh symbol
    length = ancestor_state.maps.length(obj)
    for state in states_to_merge:
        if utils.can_be_false(state.solver, state.maps.length(obj) == length):
            print("Length of map", obj, " was changed; making it symbolic")
            length = claripy.BVS("map_length", state.maps.length(obj).size())
            break

    return ancestor_state.maps[obj].flatten(
        new_length=length,
        new_invariant_conjunctions=invariant_conjs
    )