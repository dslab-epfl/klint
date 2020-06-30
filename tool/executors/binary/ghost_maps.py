import angr
from angr.state_plugins.plugin import SimStatePlugin
import claripy
from recordclass import recordclass
from executors.binary.metadata import Metadata
import executors.binary.utils as utils
from collections import namedtuple
import itertools


# "length" is symbolic, and may be larger than len(items) if there are items that are not exactly known
# "invariant" is a Boolean function on unknown items, represented as a lambda that takes an item and returns an expression
# "items" contains exactly known items, which do not have to obey the invariant
# !!! "items" is a parameterless lambda returning a list - it allows maps to refer to previous ones' items,
#     so that invariants can be defined in terms of a specific map rather than whatever the map currently is
# "key_size" is the size of keys in bits, as a non-symbolic integer
# "value_size" is the size of values in bits, as a non-symbolic integer
Map = recordclass("Map", ["length", "invariant", "items", "key_size", "value_size"])
# Items in a map can be redundant but not contradictory (i.e. there cannot be 2 items whose might be equal with values that might not be equal)
MapItem = namedtuple("MapItem", ["key", "value", "present"])

# TODO would be a cleaner API to do state.ghost_maps[obj].xxx()
class GhostMaps(SimStatePlugin):
    changed_last_merge = False # HACK: should be an instance prop, but due to the metadata HACK copying the state to get the pre-merge constants, can't...
    _length_size_in_bits = 64

    def __init__(self):
        SimStatePlugin.__init__(self)
        Metadata.set_merging_func(Map, merge_maps, pre_process=pre_process_maps, post_process=post_process_maps)
        self.changed_last_merge = False # fixed-point for merging

    def set_state(self, state):
        SimStatePlugin.set_state(self, state)

    @SimStatePlugin.memo
    def copy(self, memo):
        return GhostMaps()

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True


    # Allocates a ghost map with the given key/value sizes, and returns the associated object.
    # "obj": object; if given, use that instead of allocating an object.
    # "name": str; if given, use that name when allocating an object, useful for debugging purposes.
    # "array_length": BV64; if given, the map represents an array, meaning it already has keys from 0 to array_length-1.
    # "default_value": BV; if given, all values begin as this
    def allocate(self, key_size, value_size, obj=None, name=None, array_length=None, default_value=None):
        def to_int(n, name):
            if isinstance(n, claripy.ast.base.Base) and n.symbolic:
                raise angr.AngrExitError(name + " cannot be symbolic")
            return self.state.solver.eval(n, cast_to=int)
        key_size = to_int(key_size, "key_size")
        value_size = to_int(value_size, "value_size")

        if obj is None:
            obj = self.state.memory.allocate_opaque(name or "map_obj")


        if array_length is None:
            length = claripy.BVV(0, GhostMaps._length_size_in_bits)
            invariant = lambda i: claripy.true
        else:
            length = array_length
            invariant = lambda i: i.key.ULT(array_length) == i.present

        if default_value is not None:
            invariant = lambda i, old=invariant: claripy.And(old(i), i.value == default_value)

        self.state.metadata.set(obj, Map(length, invariant, lambda: [], key_size, value_size))
        return obj


    def length(self, obj):
        # Returns the map's length, including both known and unknown items.
        return self.state.metadata.get(Map, obj).length
    

    def key_size(self, obj):
        # Public implementation detail due to Python's untyped nature
        return self.state.metadata.get(Map, obj).key_size

    def value_size(self, obj):
        # Public implementation detail due to Python's untyped nature
        return self.state.metadata.get(Map, obj).value_size


    def add(self, obj, key, value):
        # Requires the map to not contain K.
        # Adds (K, V, true) to the known items.
        # Increments the map length.

        if utils.can_be_true(self.state.solver, self.get(obj, key)[1]):
            raise angr.AngrExitError("Cannot add a key that might already be there!")

        map = self.state.metadata.get(Map, obj)

        old_items = map.items
        new_items = lambda: old_items() + [MapItem(key, value, claripy.true)]
        self.state.metadata.set(obj, Map(map.length + 1, map.invariant, new_items, map.key_size, map.value_size), override=True)


    def remove(self, obj, key):
        # Requires the map to contain K.
        # Updates known items (K', V', P') into (K', V', P' and K != K')
        # Adds (K, V, false) to the known items.
        # Decrements the map length.

        if utils.can_be_false(self.state.solver, self.get(obj, key)[1]):
            raise angr.AngrExitError("Cannot remove a key that might not be there!")

        map = self.state.metadata.get(Map, obj)

        new_items = lambda: [MapItem(item.key, item.value, claripy.And(item.present, item.key != key)) for item in map.items()] + \
                            [MapItem(key, claripy.BVS("map_bad_value"), claripy.false)]
        self.state.metadata.set(obj, Map(map.length - 1, map.invariant, new_items, map.key_size, map.value_size), override=True)


    def get(self, obj, key):
        # If K is definitely one of the known items' keys, then return ITE(K = K1, (V1,P1), ITE(K = K2, (V2, P2), ...))
        # given known items [(K1, V1, P1), (K2, V2, P2), ...].
        # Otherwise:
        # - Let L be the number of known items whose presence bit is set
        # - Create a fresh value V and presence bit P
        # - Add the invariant on (K, V, P) to the path constraint
        # - Add P => L < length(M) to the path constraint
        # - *Mutate* the map by appending (K, V, P) to the known items
        # - Recursively return get(K)

        # backdoor used by invariant inference...
        if isinstance(obj, Map):
            map = obj
        else:
            map = self.state.metadata.get(Map, obj)

        value = claripy.BVS("map_bad_value", map.value_size)
        present = claripy.false
        key_is_known = claripy.false
        for item in map.items():
            value = claripy.If(key == item.key, item.value, value)
            present = claripy.If(key == item.key, item.present, present)
            key_is_known = claripy.Or(key == item.key, key_is_known)

        if utils.definitely_true(self.state.solver, key_is_known):
            return (value, present)

        known_len = claripy.BVV(0, GhostMaps._length_size_in_bits)
        for item in map.items():
            known_len = known_len + claripy.If(item.present, claripy.BVV(1, GhostMaps._length_size_in_bits), claripy.BVV(0, GhostMaps._length_size_in_bits))
        new_item_value = claripy.BVS("map_value", map.value_size)
        new_item_present = claripy.BoolS("map_present")
        new_item = MapItem(key, new_item_value, new_item_present)

        old_items = map.items
        # only time we actually MUTATE the map!
        map.items = lambda: old_items() + [new_item]

        # adding constraints now means that get can be called recursively from an invariant, since any recursive calls will complete through the base case above
        self.state.add_constraints(
            claripy.Or(claripy.Not(new_item_present), known_len < map.length), 
            map.invariant(new_item)
        )

        return self.get(obj, key)


    def set(self, obj, key, value):
        # Requires the map to contain K.
        # Updates known items (K', V', P') into (K', ITE(K = K', V, V'), P' or K = K')
        # Adds (K, V, true) to the known items
        if utils.can_be_false(self.state.solver, self.get(obj, key)[1]):
            raise angr.AngrExitError("Cannot set the value of a key that might not be there!")

        map = self.state.metadata.get(Map, obj)

        # While we allow duplicate items, let's try to avoid them to simplify human debugging
        new_items = lambda: [MapItem(item.key, claripy.If(item.key == key, value, item.value), claripy.Or(item.present, item.key == key)) for item in map.items() if not key.structurally_match(item.key)] + \
                            [MapItem(key, value, claripy.true)]
        self.state.metadata.set(obj, Map(map.length, map.invariant, new_items, map.key_size, map.value_size), override=True)


    def forall(self, obj, pred):
        # Let L be the number of known items whose presence bit is set
        # Create a fresh symbolic key and value pair (K', V')
        # Returns true iff:
        # - for all known items (K, V, P): P => pred(K, V)
        # - L < length(M) => (invariant(M)(K', V', true) => pred(K', V'))

        map = self.state.metadata.get(Map, obj)

        known_len = claripy.BVV(0, GhostMaps._length_size_in_bits)
        for item in map.items():
            known_len = known_len + claripy.If(item.present, claripy.BVV(1, GhostMaps._length_size_in_bits), claripy.BVV(0, GhostMaps._length_size_in_bits))

        test_key = claripy.BVS("map_test_key", map.key_size)
        test_value = claripy.BVS("map_test_value", map.value_size)
        test_item = MapItem(test_key, test_value, claripy.true)
        return claripy.And(
            *[claripy.Or(claripy.Not(item.present), pred(item.key, item.value)) for item in map.items()],
            claripy.Or(
                claripy.Not(known_len < map.length),
                claripy.Or(
                    claripy.Not(map.invariant(test_item)),
                    pred(test_key, test_value)
                )
            )
        )


    def keep_only_those_in_state(self, other_state):
        other_objs = [obj for (obj, _) in other_state.metadata.get_all(Map)]
        for (obj, _) in self.state.metadata.get_all(Map):
            if all(o is not obj for o in other_objs):
                self.state.metadata.remove(Map, obj)
                
    # Implementation details used during invariant inference
    def _known_items(self, obj): return self.state.metadata.get(Map, obj).items()
    def _invariant(self, obj): return self.state.metadata.get(Map, obj).invariant


# helper function to find FK / FV in the invariant inference algorithm
def find_f(states, o1, o2, sel1, sel2, allow_const=False):
    candidate_func = None
    for st in states:
        def filter_present(its): return [it for it in its if utils.can_be_true(st.solver, it.present)]
        items1 = filter_present(st.maps._known_items(o1))
        items2 = filter_present(st.maps._known_items(o2))
        if len(items1) > len(items2):
            # Pigeonhole: there must be an item in 1 that does not match one in 2
            return None
        if len(items1) != len(items2):
            # Lazyness: implementing backtracking in case a guess fails is hard :p
            raise angr.AngrExitError("backtracking not implemented yet")
        for x1 in map(sel1, items1):
            found = False
            for it2 in items2:
                x2 = sel2(it2)
                if candidate_func is not None:
                    if x2.structurally_match(candidate_func(x1)):
                        # All good, our candidate worked
                        found = True
                        items2.remove(it2)
                    # else: maybe next item?
                    break

                fake = claripy.BVS("fake", x1.size())
                if not x2.replace(x1, fake).structurally_match(x2):
                    # We found a possible function!
                    candidate_func = lambda x, x1=x1, x2=x2: x2.replace(x1, x)
                    found = True
                    items2.remove(it2)
                    break
                elif allow_const:
                    consts = st.solver.eval_upto(x2, 2, cast_to=int)
                    if len(consts) == 1:
                        # We found a possible constant!
                        candidate_func = lambda x, cs=consts: cs[0]
                        found = True
                        items2.remove(it2)
            if not found:
                # Found nothing in this state, give up
                return None
    # Our candidate has survived all states!
    # Don't forget to use sel1 here since we want the returned function to take an item
    return lambda i, sel1=sel1: candidate_func(sel1(i))

# helper function to copy a map and add an invariant to the copy
def add_invariant(map, inv):
    return Map(map.length, lambda i, old=map.invariant: claripy.And(old(st, i), inv(st, i)), map.items, map.key_size, map.value_size)


def maps_pre_process(states, objs):
    results = [] # pairs: (maps, lambda states, maps: returns None for no changes or maps to overwrite them)
    
    # Invariant inference algorithm
    for (o1, o2) in itertools.permutations(objs, 2):
        # Step 1: Length.
        # For each pair of maps (M1, M2), 
        #   if length(M1) <= length(M2) across all states,
        #   then assume this holds the merged state
        if all(utils.definitely_true(st.solver, st.maps.length(o1) <= st.maps.length(o2)) for st in states):
            results.append(([], lambda st, _, o1=o1, o2=o2: st.add_constraints(st.maps.length(o1) <= st.maps.length(o2))))
            
        # Step 2: Cross-references.
        # For each pair of maps (M1, M2),
        #  if all items in M1 are known across all states,
        #  and there exists a function FK such that for all items (K, V, P) in M1, P => get(M2, FK(K, V)) = (?, true),
        #  then assume this is an invariant of M1 in the merged state.
        #  Additionally,
        #   if there exists a function FV such that for all items (K, V, P) in M1, P => get(M2, FK(K, V)) = (FV(K, V), true),
        #   then assume this is an invariant of M1 in the merged state.
        if all(utils.definitely_true(st.solver, st.maps.length(o1) == len(st.maps._known_items(o1))) for st in states):
            fk = find_f(states, o1, o2, lambda i: i.key, lambda i: i.key) \
              or find_f(states, o1, o2, lambda i: i.value, lambda i: i.key)
            if fk is not None:
                
                results.append(([o1, o2], lambda st, ms: [add_invariant(ms[0], lambda i: claripy.Or(claripy.Not(p), ms[1].get(fk(i))[1])), ms[1]]))
                fv = find_f(states, o1, o2, lambda i: i.key, lambda i: i.value, allow_const=True) \
                  or find_f(states, o1, o2, lambda i: i.value, lambda i: i.value, allow_const=True)
                if fv is not None:
                    results.append(([o1, o2], lambda st, ms: [add_invariant(ms[0], lambda i: claripy.Or(claripy.Not(p), ms[1].get(fk(i))[0] == fv(i))), ms[1]]))
    return results

def maps_merge(states, obj):
    # Sanity check: the unknown items invariant has not changed, and neither did the key/value size
    if any(st.maps._invariant(obj) != states[0].maps._invariant(obj) or \
           st.maps.key_size(obj) != states[0].maps.key_size(obj) or \
           st.maps.value_size(obj) != states[0].maps.value_size(obj) \
           for st in states[1:]):
        raise angr.AngrExitError("Maps do not match!")

    # Oblivion algorithm: "forget" known items by integrating them into the unknown items invariant
    # For each known item, if the unknown items invariant does not hold on that item, find constraints that do hold and add them as a disjunction to the invariant.
    invariant = maps[0].invariant
    for st in states:
        for item in st.maps._known_items(obj):
            if utils.can_be_false(st.solver, invariant(st, item)):
                new = ...
                invariant = lambda i, old=invariant: claripy.Or(old(st, i), new(st, i))


def merge_maps(maps, states):
    def get_constraint(state, expr):
        maybe_constant = state.solver.eval_upto(expr, 2)
        if len(maybe_constant) == 1:
            return expr == maybe_constant[0]
        # Might miss a lot of stuff but will do for now, this is sound since having overly lax invariants can lead to nonexistent paths but not to ignored ones
        return claripy.And(*[cons for cons in state.solver.constraints if next((c for c in cons.children_asts() if c.structurally_match(expr)), None) is not None])

    map = maps[0]
    state = states[0]
    if any(m.invariants != map.invariants or m.key_size != map.key_size or m.value_size != map.value_size for m in maps[1:]):
        raise angr.AngrExitError("Maps do not match!")

    invariants = []
    has_changed = False

    # If any invariant does not apply to an item, add an OR so it does
    # Using "== item.key/value" is likely pointless since their constraints will no longer exist after the merge because they refer to variables within an iteration
    # Instead, try to collect constraints about the key/value
    for inv in map.invariants + ([lambda st, k, v, p: claripy.false] if len(map.invariants) == 0 else []):
        alternatives = []
        for (m, st) in zip(maps, states):
            for item in m.items():
                if utils.can_be_true(st.solver, item.present) and utils.definitely_false(st.solver, inv(st, item.key, item.value, item.present)):
                    has_changed = True
                    key_cons = get_constraint(st, item.key)
                    value_cons = get_constraint(st, item.value)
                    real_item_key = item.key # avoid capture
                    real_item_value = item.value
                    alternatives.append(lambda st, k, v, p: claripy.And(key_cons.replace(real_item_key, k), value_cons.replace(real_item_value, v)))
        inv_copy = inv # avoid capture
        invariants.append(lambda st, k, v, p: claripy.Or(inv_copy(st, k, v, p), *[i(st, k, v, p) for i in alternatives]))

    # If the length differs across states, make it unconstrained and add an unknown element to the invariants
    result_length = map.length
    for m in maps[1:]:
        if not m.length.structurally_match(map.length):
            has_changed = True
            result_length = states[0].solver.BVS("map_merged_length", GhostMaps._length_size_in_bits)
            invariants.append(lambda st, k, v, p: claripy.Or(claripy.Not(claripy.BoolS("map_has")), p))
            break

    if has_changed:
        GhostMaps.changed_last_merge = True
    return Map(result_length, invariants, lambda: [], map.key_size, map.value_size)

def post_process_maps(state, result):
    if not GhostMaps.changed_last_merge:
        return
    for (objs, lam, extra) in result:
        maps = [state.metadata.get(Map, o) for o in objs]
        new_maps = lam(state, objs, maps, extra)
        for (o, m) in zip(objs, new_maps):
            state.metadata.set(o, m, override=True)
    return
