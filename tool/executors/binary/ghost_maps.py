import angr
from angr.state_plugins.plugin import SimStatePlugin
import claripy
from recordclass import recordclass
from executors.binary.metadata import Metadata
import executors.binary.utils as utils
from collections import namedtuple

# HUGE HACK
# Claripy doesn't support uninterpreted functions, and adding that support would probably take a while, so...
# this creates a pseudo-UF that is really a symbol lookup table; it will return different symbols
# if two equal but not structurally equivalent values are passed in
# but this is sound because it can only result in over-approximation
debug_log_ufs = [] # TODO remove this - but useful for debugging
def CreateUninterpretedFunction(name, creator):
    def func(state, value, _cache={}):
        # HACK avoid needless concat+extract, to canonicalize a bit, this is needed due to how array indexing works
        # (the index in an array whose elements have size 2^N and the one in an array whose elements have size 2^M
        #  are the same in practice but cut off a different number of bits!)
        if value.op == "Concat" \
           and value.args[0].structurally_match(claripy.BVV(0, value.args[0].size())) \
           and value.args[1].op == "Extract" \
           and utils.definitely_true(state.solver, value.args[1].args[2] == value):
            value = value.args[1].args[2]
        debug_log_ufs.append((name,value))
        return _cache.setdefault(str(value), creator(name + "_UF"))
    return func

# Helper function to make expressions clearer
def Implies(a, b):
    return claripy.Or(claripy.Not(a), b)

# "length" is symbolic, and may be larger than len(items) if there are items that are not exactly known
# "invariant" is a function that represents unknown items: a lambda that takes (state, item) and returns a Boolean expression
# "items" contains exactly known items, which do not have to obey the invariant
# "key_size" is the size of keys in bits, as a non-symbolic integer
# "value_size" is the size of values in bits, as a non-symbolic integer
Map = recordclass("Map", ["length", "invariant", "items", "key_size", "value_size", "value_func", "present_func"])
MapItem = namedtuple("MapItem", ["key", "value", "present"])

class GhostMaps(SimStatePlugin):
    _length_size_in_bits = 64 # TODO should only be default for maps that don't provide an array_length

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
            invariant = lambda st, i, f: claripy.Not(i.present)
        else:
            length = array_length
            invariant = lambda st, i, f: i.key.ULT(array_length) == i.present

        if default_value is not None:
            invariant = lambda st, i, f, old=invariant: claripy.And(old(st, i, f), i.value == default_value)

        value_func = CreateUninterpretedFunction((name or "map") + "_value", lambda n: claripy.BVS(n, value_size))
        present_func = CreateUninterpretedFunction((name or "map") + "_present", lambda n: claripy.BoolS(n))

        obj = self.state.memory.allocate_opaque(name or "map_obj")
        self.state.metadata.set(obj, Map(length, invariant, [], key_size, value_size, value_func, present_func))
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

        new_items = [MapItem(key, value, claripy.true)] + map.items
        self.state.metadata.set(obj, Map(map.length + 1, map.invariant, new_items, map.key_size, map.value_size, map.value_func, map.present_func), override=True)


    def remove(self, obj, key):
        # Requires the map to contain K.
        # Updates known items (K', V', P') into (K', V', P' and K != K')
        # Adds (K, V, false) to the known items.
        # Decrements the map length.

        if utils.can_be_false(self.state.solver, self.get(obj, key)[1]):
            raise angr.AngrExitError("Cannot remove a key that might not be there!")

        map = self._get_map(obj)

        new_items = [MapItem(key, claripy.BVS("map_bad_value", map.value_size), claripy.false)] + \
                    [MapItem(i.key, i.value, claripy.And(i.present, i.key != key)) for i in map.items]
        self.state.metadata.set(obj, Map(map.length - 1, map.invariant, new_items, map.key_size, map.value_size, map.value_func, map.present_func), override=True)


    def get(self, obj, key, fuel=1):
        # Let V = valuefunc(M)(K), P = presentfunc(M)(K)
        # Add P => L < length(M) to the path constraint
        # Add invariant(M)(K, V, P) to the path constraint
        # Return ITE(K = K1, (V1,P1), ITE(K = K2, (V2, P2), ... (V, P)))
        # given known items [(K1, V1, P1), (K2, V2, P2), ...].

        map = self._get_map(obj)

        value = map.value_func(self.state, key)
        present = map.present_func(self.state, key)
        key_is_known = claripy.false
        for item in map.items:
            value = claripy.If(key == item.key, item.value, value)
            present = claripy.If(key == item.key, item.present, present)
            key_is_known = claripy.Or(key_is_known, key == item.key)

        # Only add constraints if there's a chance they might be useful
        if utils.can_be_false(self.state.solver, key_is_known):
            self.state.add_constraints(
                Implies(present, self._known_length(obj) < map.length),
                map.invariant(self.state, MapItem(key, value, present), fuel-1)
            )
            if not self.state.satisfiable():
                raise "this should never happen"

        return (value, present)


    def set(self, obj, key, value):
        # Requires the map to contain K.
        # Updates known items (K', V', P') into (K', ITE(K = K', V, V'), P' or K = K')
        # Adds (K, V, true) to the known items
        if utils.can_be_false(self.state.solver, self.get(obj, key)[1]):
            raise angr.AngrExitError("Cannot set the value of a key that might not be there!")

        map = self._get_map(obj)

        # Try to avoid duplicate items if possible, it makes debugging and reasoning simpler
        new_items = [MapItem(key, value, claripy.true)] + \
                    [MapItem(i.key, claripy.If(i.key == key, value, i.value), claripy.And(i.present, i.key != key)) for i in map.items if not i.key.structurally_match(key)]
        self.state.metadata.set(obj, Map(map.length, map.invariant, new_items, map.key_size, map.value_size, map.value_func, map.present_func), override=True)


    def forall(self, obj, pred, fuel=1):
        # Let L be the number of known items whose presence bit is set
        # Create a fresh symbolic key K' and a fresh symbolic value V'
        # Let F = ((P1 => pred(K1, V1)) and (P2 => pred(K2, V2)) and (...) and ((L < length(M)) => (invariant(M)(K', V') => pred(K', V'))))
        # Add F => pred(K, V) to the map's invariant
        # Return F

        map = self._get_map(obj)

        known_len = self._known_length(obj)

        test_key = claripy.BVS("map_test_key", map.key_size)
        test_value = claripy.BVS("map_test_value", map.value_size)

        result = claripy.And(
            *[Implies(i.present, pred(i.key, i.value)) for i in map.items],
            Implies(
                known_len < map.length,
                Implies(
                    map.invariant(self.state, MapItem(test_key, test_value, claripy.true), fuel-1), 
                    pred(test_key, test_value)
                )
            )
        )

        # MUTATE the map!
        # ... but only if there's a chance it's useful, let's not needlessly complicate the invariant
        if len(self.state.solver.eval_upto(result, 2)) == 2:
            map.invariant = lambda st, i, f, old=map.invariant: claripy.And(Implies(result, pred(i.key, i.value)), old(st, i, f))

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
    def _value_func(self, obj): return self._get_map(obj).value_func
    def _present_func(self, obj): return self._get_map(obj).present_func


# TODO in metadata: adapt signatures to the ones here, automatically do the "remove metadata from objs not in the ancestor"

def maps_merge_across(states_to_merge, objs, ancestor_state):
    results = [] # pairs: (ID, maps, lambda states, maps: returns None for no changes or maps to overwrite them)
    states = states_to_merge + [ancestor_state]

    # helper function to find FK / FV in the invariant inference algorithm
    # returns (F, F', is_const) where F' is the opposite function, or (None, None, False) if not found
    # if allow_const then F(i) might return a constant in which case F' is definitely None and is_const is True...
    def find_f(o1, o2, sel1, sel2, allow_const=False):
        # guess F', which is not easy...
        def guess_f_rev(state, x1, x2):
            # x2 == x1
            if x2.structurally_match(x1):
                return lambda x: x
            # x2 == x1[N:0]
            if x2.op == "Concat" \
               and x2.args[0].structurally_match(claripy.BVV(0, x2.args[0].size())) \
               and x2.args[1].op == "Extract" \
               and utils.definitely_true(state.solver, x2.args[1].args[2] == x1):
                return lambda x: x
            return None

        candidate_func = None
        candidate_rev = None
        is_const = False
        for state in states:
            def filter_present(its): return [it for it in its if utils.definitely_true(state.solver, it.present)]
            items1 = filter_present(state.maps._known_items(o1))
            items2 = filter_present(state.maps._known_items(o2))
            if len(items1) == 0:
                # If there are no items in 1 it's fine but doesn't give us info either
                continue
            if len(items1) > len(items2):
                # Pigeonhole: there must be an item in 1 that does not match one in 2
                return (None, None, False)
            if len(items1) != len(items2):
                # Lazyness: implementing backtracking in case a guess fails is hard :p
                raise angr.AngrExitError("backtracking not implemented yet")
            for x1 in map(sel1, items1):
                found = False
                for it2 in items2:
                    x2 = sel2(it2)
                    if candidate_func is not None:
                        # 1st is for replacement, 2nd is for constants
                        if x2.structurally_match(candidate_func(x1)) or utils.definitely_true(state.solver, x2 == candidate_func(x1)):
                            # All good, our candidate worked
                            found = True
                            items2.remove(it2)
                        # else: maybe next item?
                        break
                    fake = claripy.BVS("fake", x1.size())
                    if not x2.replace(x1, fake).structurally_match(x2):
                        # We found a possible function!
                        candidate_func = lambda x, x1=x1, x2=x2: x2.replace(x1, x)
                        candidate_rev = guess_f_rev(state, x1, x2)
                        found = True
                        items2.remove(it2)
                        break
                    elif allow_const:
                        consts = state.solver.eval_upto(x2, 2, cast_to=int)
                        if len(consts) == 1:
                            # We found a possible constant!
                            candidate_func = lambda x, consts=consts, sz=x2.size(): claripy.BVV(consts[0], sz)
                            is_const = True
                            found = True
                            items2.remove(it2)
                if not found:
                    # Found nothing in this state, give up
                    return (None, None, False)
        # Our candidate has survived all states!
        # Don't forget to use sels here since we want the returned functions to take an item
        return (lambda i: candidate_func(sel1(i)), lambda i: candidate_rev(sel2(i)), is_const)

    # helper function to copy a map and add an invariant to the copy
    def add_invariant(map, inv):
        return Map(map.length, lambda st, i, f: claripy.And(map.invariant(st, i, f), inv(st, i, f)), map.items, map.key_size, map.value_size, map.value_func, map.present_func)

    # Optimization: Ignore maps that have not changed at all, e.g. those that are de facto readonly after initialization
    objs = [o for o in objs if any(not utils.structural_eq(ancestor_state.maps._get_map(o), st.maps._get_map(o)) for st in states)]

    # Invariant inference algorithm: if some property P holds in all states to merge and the ancestor state, optimistically assume it is part of the invariant
    for o1 in objs:
        for o2 in objs:
            if o1 is o2: continue
            print("Inferring invariants for", o1, o2)

            # Step 1: Length.
            # For each pair of maps (M1, M2),
            #   if length(M1) <= length(M2) across all states,
            #   then assume this holds the merged state
            if all(utils.definitely_true(st.solver, st.maps.length(o1) <= st.maps.length(o2)) for st in states):
                results.append(("length", [o1, o2], lambda st, ms: st.add_constraints(ms[0].length <= ms[1].length)))

            # Step 2: Cross-references.
            # For each pair of maps (M1, M2),
            #  if there exists a function FK such that in all states, forall(M1, (K,V): get(M2, FK(K, V)) == (_, true)),
            #  then assume this is an invariant of M1 in the merged state.
            #  Additionally,
            #   if there exists a function FV such that in all states, forall(M1, (K,V): get(M2, FK(K, V)) == (FV(K, V), true)),
            #   then assume this is an invariant of M1 in the merged state.
            #   Additionally,
            #   if FV returns a constant,
            #   and if in all states, forall(M2, (K,V): V == FV(_) => get(M1, FK-1(K,V)) == (_, true)),
            #   then assume this is an invariant of M2 in the merged state.
            # TODO: a string ID is not really enough to guarantee the constraints are the same here...
            # TODO explain why we use 'obj' directly and it works (even if the same key whose val is set by a cross-val was added in the meantime)
            fk, fkr, _ = find_f(o1, o2, lambda i: i.key, lambda i: i.key)
            o1key = True
            if fk is None:
                fk, fkr, _ = find_f(o1, o2, lambda i: i.value, lambda i: i.key)
                o1key = False
            if fk and all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v, st=st, o2=o2, fk=fk: st.maps.get(o2, fk(MapItem(k, v, claripy.true)))[1])) for st in states):
                results.append(("cross-key", [o1, o2], lambda state, maps, o2=o2, fk=fk: [add_invariant(maps[0], lambda st, i, f, fk=fk, o2=o2: Implies(i.present, st.maps.get(o2, fk(i), fuel=f)[1]) if f >= 0 else claripy.true), maps[1]]))
                fv, _, fvc = find_f(o1, o2, lambda i: i.key, lambda i: i.value, allow_const=True)
                if fv is None: fv, _, fvc = find_f(o1, o2, lambda i: i.value, lambda i: i.value, allow_const=True)
                if fv and all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v, st=st, o2=o2, fk=fk, fv=fv: st.maps.get(o2, fk(MapItem(k, v, claripy.true)))[0] == fv(MapItem(k, v, claripy.true)))) for st in states):
                    results.append(("cross-value", [o1, o2], lambda state, maps, o2=o2, fk=fk, fv=fv: [add_invariant(maps[0], lambda st, i, f, fk=fk, fv=fv, o2=o2: Implies(i.present, st.maps.get(o2, fk(i), fuel=f)[0] == fv(i)) if f >= 0 else claripy.true), maps[1]]))
                    if o1key and fkr and fvc and all(utils.definitely_true(st.solver, st.maps.forall(o2, lambda k, v, st=st, o1=o1, fkr=fkr, fv=fv: Implies(v == fv(MapItem(None,None,None)), st.maps.get(o1, fkr(MapItem(k, v, claripy.true)))[1]))) for st in states):
                        results.append(("cross-rev-value", [o1, o2], lambda state, maps, o1=o1, fkr=fkr, fv=fv: [maps[0], add_invariant(maps[1], lambda st, i, f, o1=o1, fkr=fkr, fv=fv: Implies(i.present, Implies(i.value == fv(MapItem(None,None,None)), st.maps.get(o1, fkr(i), fuel=f)[1])) if f >= 0 else claripy.true)]))

    print("Cross-map inference done!")
    return results

def maps_merge_one(states_to_merge, obj, ancestor_state):
    print("Merging map", obj)
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
    for state in states_to_merge:
        # Step 1: invariant.
        # For each known item,
        #  if the unknown items invariant may not hold on that item assuming the item is present,
        #  find constraints that do hold and add them as a disjunction to the invariant.
        for item in state.maps._known_items(obj):
            if utils.definitely_true(state.solver, claripy.And(item.present, claripy.Not(invariant(state, item, 1)))):
                key_constraints = find_constraints(state, item.key)
                value_constraints = find_constraints(state, item.value)
                invariant = lambda st, i, f, old=invariant, ik=item.key, iv=item.value, kc=key_constraints, vc=value_constraints: \
                                claripy.Or(old(st, i, f), claripy.And(kc.replace(ik, i.key), vc.replace(iv, i.value)))
        # Step 2: length.
        # If the length may have changed in any state from the one in the ancestor state,
        # replace the length with a fresh symbol
        if not length_changed and utils.can_be_false(state.solver, state.maps.length(obj) == length):
            length = claripy.BVS("map_length", GhostMaps._length_size_in_bits)
            func_has = CreateUninterpretedFunction("map_has", lambda n: claripy.BoolS(n))
            invariant = lambda st, i, f, func_has=func_has, old=invariant: claripy.And(Implies(i.present, func_has(st, i.key)), old(st, i, f))

    return Map(
        length,
        invariant,
        ancestor_state.maps._known_items(obj),
        ancestor_state.maps.key_size(obj),
        ancestor_state.maps.value_size(obj),
        ancestor_state.maps._value_func(obj),
        ancestor_state.maps._present_func(obj)
    )