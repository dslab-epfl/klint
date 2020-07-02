import angr
from angr.state_plugins.plugin import SimStatePlugin
import claripy
from recordclass import recordclass
from executors.binary.metadata import Metadata
import executors.binary.utils as utils
from collections import namedtuple
import itertools

# TODO better name + "time travel" explanation
# TODO FIXME deal with duplicate items - they can be retroactively added behind our back!
class ChainedList:
    def __init__(self, head=None, tail=None, tail_mapper=None, tail_filter=None):
        self.values = [head] if head is not None else []
        self.tail = tail or []
        self.tail_mapper = tail_mapper or (lambda i: i)
        self.tail_filter = tail_filter or (lambda i: True)

    def append(self, item):
        self.values.append(item)

    def __iter__(self):
        return itertools.chain(self.values, (self.tail_mapper(x) for x in self.tail if self.tail_filter(x)))

    def __copy__(self):
        return ChainedList(tail=self)

    def __deepcopy__(self, memo):
        result = self.__copy__()
        memo[id(result)] = result
        return result

# "length" is symbolic, and may be larger than len(items) if there are items that are not exactly known
# "invariant" is a Boolean function on unknown items, represented as a lambda that takes an item and returns an expression
# "items" contains exactly known items, which do not have to obey the invariant
# "key_size" is the size of keys in bits, as a non-symbolic integer
# "value_size" is the size of values in bits, as a non-symbolic integer
Map = recordclass("Map", ["length", "invariant", "items", "key_size", "value_size"])
MapItem = namedtuple("MapItem", ["key", "value", "present"])

class GhostMaps(SimStatePlugin):
    _length_size_in_bits = 64

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


    def _get_map(self, obj):
        # Invariant inference calls some functions on specific maps
        if isinstance(obj, Map):
            return obj
        else:
            return self.state.metadata.get(Map, obj)


    # Allocates a ghost map with the given key/value sizes, and returns the associated object.
    # "name": str; if given, use that name when allocating an object, useful for debugging purposes.
    # "array_length": BV64; if given, the map represents an array, meaning it already has keys from 0 to array_length-1.
    # "default_value": BV; if given, all values begin as this
    def allocate(self, key_size, value_size, name=None, array_length=None, default_value=None):
        def to_int(n, name):
            if isinstance(n, claripy.ast.base.Base) and n.symbolic:
                raise angr.AngrExitError(name + " cannot be symbolic")
            return self.state.solver.eval(n, cast_to=int)
        key_size = to_int(key_size, "key_size")
        value_size = to_int(value_size, "value_size")

        if array_length is None:
            length = claripy.BVV(0, GhostMaps._length_size_in_bits)
            invariant = lambda i: claripy.true
        else:
            length = array_length
            invariant = lambda i: i.key.ULT(array_length) == i.present

        if default_value is not None:
            invariant = lambda i, old=invariant: claripy.And(old(i), i.value == default_value)

        obj = self.state.memory.allocate_opaque(name or "map_obj")
        self.state.metadata.set(obj, Map(length, invariant, ChainedList(), key_size, value_size))
        return obj


    def length(self, obj):
        # Returns the map's length, including both known and unknown items.
        return self._get_map(obj).length
    

    def key_size(self, obj):
        # Public implementation detail due to Python's untyped nature
        return self._get_map(obj).key_size

    def value_size(self, obj):
        # Public implementation detail due to Python's untyped nature
        return self._get_map(obj).value_size


    def add(self, obj, key, value):
        # Requires the map to not contain K.
        # Adds (K, V, true) to the known items.
        # Increments the map length.

        if utils.can_be_true(self.state.solver, self.get(obj, key)[1]):
            raise angr.AngrExitError("Cannot add a key that might already be there!")

        map = self._get_map(obj)

        new_items = ChainedList(
            head=MapItem(key, value, claripy.true),
            tail=map.items
        )
        self.state.metadata.set(obj, Map(map.length + 1, map.invariant, new_items, map.key_size, map.value_size), override=True)


    def remove(self, obj, key):
        # Requires the map to contain K.
        # Updates known items (K', V', P') into (K', V', P' and K != K')
        # Adds (K, V, false) to the known items.
        # Decrements the map length.

        if utils.can_be_false(self.state.solver, self.get(obj, key)[1]):
            raise angr.AngrExitError("Cannot remove a key that might not be there!")

        map = self._get_map(obj)

        new_items = ChainedList(
            head=MapItem(key, claripy.BVS("map_bad_value", map.value_size), claripy.false),
            tail=map.items,
            tail_mapper=lambda i: MapItem(i.key, i.value, claripy.And(i.present, i.key != key))
        )
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

        map = self._get_map(obj)

        value = claripy.BVS("map_bad_value", map.value_size)
        present = claripy.false
        key_is_known = claripy.false
        for item in map.items:
            value = claripy.If(key == item.key, item.value, value)
            present = claripy.If(key == item.key, item.present, present)
            key_is_known = claripy.Or(key == item.key, key_is_known)

        if utils.definitely_true(self.state.solver, key_is_known):
            return (value, present)

        known_len = self._known_length(obj)
        new_item_value = claripy.BVS("map_value", map.value_size)
        new_item_present = claripy.BoolS("map_present")
        new_item = MapItem(key, new_item_value, new_item_present)

        # MUTATE the map!
        map.items.append(new_item)

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

        map = self._get_map(obj)

        # Try to avoid duplicate items if possible, it makes debugging and reasoning simpler
        new_items = ChainedList(
            head=MapItem(key, value, claripy.true),
            tail=map.items,
            tail_mapper=lambda i: MapItem(i.key, claripy.If(i.key == key, value, i.value), claripy.And(i.present, i.key != key)),
            tail_filter=lambda i: not i.key.structurally_match(key)
        )
        self.state.metadata.set(obj, Map(map.length, map.invariant, new_items, map.key_size, map.value_size), override=True)


    def forall(self, obj, pred):
        # Let L be the number of known items whose presence bit is set
        # Create a fresh symbolic bit F, a fresh symbolic key K' and a fresh symbolic value V'
        # Add F <=> ((P1 => pred(K1, V1)) and (P2 => pred(K2, V2)) and (...) and ((L < length(M)) => (invariant(M)(K', V', true) => pred(K', V')))) to the path constraint
        # Add F => pred(K, V) to the map's invariant
        # Return F

        map = self._get_map(obj)

        known_len = self._known_length(obj)

        result = claripy.BoolS("map_forall")
        test_key = claripy.BVS("map_test_key", map.key_size)
        test_value = claripy.BVS("map_test_value", map.value_size)

        self.state.add_constraints(
            result == claripy.And(
                          *[claripy.Or(claripy.Not(i.present), pred(i.key, i.value)) for i in map.items],
                          claripy.Or(
                              claripy.Not(known_len < map.length),
                              claripy.Or(
                                  claripy.Not(map.invariant(MapItem(test_key, test_value, claripy.true))),
                                  pred(test_key, test_value)
                              )
                          )
                      )
        )
        if not self.state.satisfiable():
            raise "wut"

        # MUTATE the map!
        # ... but only if there's a chance it's useful, let's not needlessly complicate the invariant
        if utils.can_be_true(self.state.solver, result):
            map.invariant = lambda i, old=map.invariant: claripy.And(claripy.Or(claripy.Not(result), pred(i.key, i.value)), old(i))

        return result


    # Implementation detail used by other functions & invariant inference
    def _known_length(self, obj):
        map = self._get_map(obj)
        known_len = claripy.BVV(0, GhostMaps._length_size_in_bits)
        for item in map.items:
            known_len = known_len + claripy.If(item.present, claripy.BVV(1, GhostMaps._length_size_in_bits), claripy.BVV(0, GhostMaps._length_size_in_bits))
        return known_len

    # Implementation details used during invariant inference
    def _known_items(self, obj): return self._get_map(obj).items
    def _invariant(self, obj): return self._get_map(obj).invariant


# TODO in metadata: adapt signatures to the ones here, automatically do the "remove metadata from objs not in the ancestor"

def maps_merge_across(states_to_merge, objs, ancestor_state):
    results = [] # pairs: (ID, maps, lambda states, maps: returns None for no changes or maps to overwrite them)
    states = states_to_merge + [ancestor_state]

    # helper function to find FK / FV in the invariant inference algorithm
    def guess_f(o1, o2, sel1, sel2, allow_const=False):
        for st in states:
            def filter_present(its): return [it for it in its if utils.can_be_true(st.solver, it.present)]
            items1 = filter_present(st.maps._known_items(o1))
            items2 = filter_present(st.maps._known_items(o2))
            for x1 in map(sel1, items1):
                for x2 in map(sel2, items2):
                    fake = claripy.BVS("fake", x1.size())
                    if not x2.replace(x1, fake).structurally_match(x2):
                        # x2 contains x1, we found a possible function!
                        yield lambda i, x1=x1, x2=x2: x2.replace(x1, sel1(i))
                    elif allow_const:
                        consts = st.solver.eval_upto(x2, 2, cast_to=int)
                        if len(consts) == 1:
                            # x2 is a constant, we found a possible constant!
                            yield lambda i, consts=consts, sz=x2.size(): claripy.BVV(consts[0], sz)

    # helper function to copy a map and add an invariant to the copy
    def add_invariant(map, inv):
        return Map(map.length, lambda i: claripy.And(map.invariant(i), inv(i)), map.items, map.key_size, map.value_size)

    if any(not st.satisfiable() for st in states):
        raise "waaat"

    # Invariant inference algorithm: if some property P holds in all states to merge and the ancestor state, optimistically assume it is part of the invariant
    for o1 in objs:
        all_o1_items_known = all(utils.definitely_true(st.solver, st.maps.length(o1) == st.maps._known_length(o1)) for st in states)
        for o2 in objs:
            if o1 is o2: continue

            # Step 1: Length.
            # For each pair of maps (M1, M2),
            #   if length(M1) <= length(M2) across all states,
            #   then assume this holds the merged state
            if all(utils.definitely_true(st.solver, st.maps.length(o1) <= st.maps.length(o2)) for st in states):
                results.append(("length", [o1, o2], lambda st, ms: st.add_constraints(ms[0].length <= ms[1].length)))

            # Step 2: Cross-references.
            # For each pair of maps (M1, M2),
            #  if there exists a function FK such that in all states, for all items (K, V, P) in M1, P => get(M2, FK(K, V)) = (_, true),
            #  then assume this is an invariant of M1 in the merged state.
            #  Additionally,
            #   if there exists a function FV such that in all states, for all items (K, V, P) in M1, P => get(M2, FK(K, V)) = (FV(K, V), true),
            #   then assume this is an invariant of M1 in the merged state.
            # TODO: a string ID is not really enough to guarantee the constraints are the same here...
            aaa = list(itertools.chain(guess_f(o1, o2, lambda i: i.key, lambda i: i.key), guess_f(o1, o2, lambda i: i.value, lambda i: i.key)))
            for fk in itertools.chain(guess_f(o1, o2, lambda i: i.key, lambda i: i.key), guess_f(o1, o2, lambda i: i.value, lambda i: i.key)):
                if all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v: st.maps.get(o2, fk(MapItem(k, v, claripy.true)))[1])) for st in states):
                    results.append(("cross-key", [o1, o2], lambda st, ms, fk=fk: [add_invariant(ms[0], lambda i, st=st, ms=ms, fk=fk: claripy.Or(claripy.Not(i.present), st.maps.get(ms[1], fk(i))[1])), ms[1]]))
                    for fv in itertools.chain(guess_f(o1, o2, lambda i: i.key, lambda i: i.value, allow_const=True), guess_f(o1, o2, lambda i: i.value, lambda i: i.value, allow_const=True)):
                        if all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v: st.maps.get(o2, fk(MapItem(k, v, claripy.true)))[0] == fv(MapItem(k, v, claripy.true)))) for st in states):
                            results.append(("cross-value", [o1, o2], lambda st, ms, fk=fk, fv=fv: [add_invariant(ms[0], lambda i, st=st, ms=ms, fk=fk, fv=fv: claripy.Or(claripy.Not(i.present), st.maps.get(ms[1], fk(i))[0] == fv(i))), ms[1]]))
    return results

def maps_merge_one(states_to_merge, obj, ancestor_state):
    # helper function to find constraints that hold on an expression in a state
    def find_constraints(state, expr):
        # If the expression is constant or constrained to be, return that
        constants = state.solver.eval_upto(expr, 2)
        if len(constants) == 1:
            return expr == constants[0]
        # Otherwise, find constraints that contain the expression
        # This might miss stuff due to transitive constraints,
        # but it's sound since having overly lax invariants can only over-approximate
        fake = claripy.BVS("fake", expr.size())
        return claripy.And(*[cons for cons in state.solver.constraints if not cons.replace(expr, fake).structurally_match(cons)])

    # Oblivion algorithm: "forget" known items by integrating them into the unknown items invariant
    invariant = ancestor_state.maps._invariant(obj)
    length = ancestor_state.maps.length(obj)
    length_changed = False
    for st in states_to_merge:
        # Step 1: invariant.
        # For each known item, 
        #  if the unknown items invariant may not hold on that item assuming the item is present,
        #  find constraints that do hold and add them as a disjunction to the invariant.
        for item in st.maps._known_items(obj):
            if utils.can_be_true(st.solver, claripy.And(item.present, claripy.Not(invariant(item)))):
                key_constraints = find_constraints(st, item.key)
                value_constraints = find_constraints(st, item.value)
                invariant = lambda i, old=invariant, ik=item.key, iv=item.value, kc=key_constraints, vc=value_constraints: \
                                claripy.Or(old(i), claripy.And(kc.replace(ik, i.key), vc.replace(iv, i.value)))
        # Step 2: length.
        # If the length may have changed in any state from the one in the ancestor state,
        # replace the length with a fresh symbol
        if not length_changed and utils.can_be_false(st.solver, st.maps.length(obj) == length):
            length = claripy.BVS("map_length", GhostMaps._length_size_in_bits)

    return Map(length, invariant, ancestor_state.maps._known_items(obj), ancestor_state.maps.key_size(obj), ancestor_state.maps.value_size(obj))