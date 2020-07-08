import angr
from angr.state_plugins.plugin import SimStatePlugin
import claripy
from recordclass import recordclass
from executors.binary.metadata import Metadata
import executors.binary.utils as utils
from collections import namedtuple

# note: we use size-1 bitvectors instead of bools cause they sometimes behave weirdly in angr..
# e.g. sometimes (p and not(p)) is true :/

# HUGE HACK
# Claripy doesn't support uninterpreted functions, and adding that support would probably take a while, so...
def CreateUninterpretedFunction(name, creator):
    def func(state, value, _cache=[]):
        for (k, v) in _cache:
            if k.structurally_match(value):
                return v
        f = creator(name + "_UF")
        state.add_constraints(*[Implies(k == value, f == v) for (k, v) in _cache])
        _cache.append((value, f))
        return f
    return func

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

# "length" is symbolic, and may be larger than len(items) if there are items that are not exactly known
# "invariants" is a list of conjunctions that represents unknown items: each is a lambda that takes (state, item) and returns a Boolean expression
# "items" contains exactly known items, which do not have to obey the invariants
# "key_size" is the size of keys in bits, as a non-symbolic integer
# "value_size" is the size of values in bits, as a non-symbolic integer
Map = recordclass("Map", ["name", "length", "invariants", "items", "key_size", "value_size", "value_func", "present_func"])
MapItem = namedtuple("MapItem", ["key", "value", "present"])

class GhostMaps(SimStatePlugin):
    _length_size_in_bits = 64 # TODO should only be default for maps that don't provide an array_length
    _name_counter = 0

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


    # Allocates a ghost map with the given key/value sizes, and returns the associated object.
    # "name": str; if given, use that name when allocating an object, useful for debugging purposes.
    # "array_length": BV64; if given, the map represents an array, meaning it already has keys from 0 to array_length-1.
    # "default_value": BV; if given, all values begin as this
    def allocate(self, key_size, value_size, name=None, array_length=None, default_value=None):
        def to_int(n, name):
            if isinstance(n, claripy.ast.base.Base) and n.symbolic:
                raise (name + " cannot be symbolic")
            return self.state.solver.eval_one(n, cast_to=int)
        key_size = to_int(key_size, "key_size")
        value_size = to_int(value_size, "value_size")

        name = (name or "map") + "_" + str(GhostMaps._name_counter)
        GhostMaps._name_counter = GhostMaps._name_counter + 1

        if array_length is None:
            length = claripy.BVV(0, GhostMaps._length_size_in_bits)
            invariants = [lambda st, i, _: i.present == 0]
        else:
            length = array_length
            invariants = [lambda st, i, _: (i.key < array_length) == (i.present == 1)]

        if default_value is not None:
            invariants.append(lambda st, i, _: i.value == default_value)

        value_func = CreateUninterpretedFunction((name or "map") + "_value", lambda n: claripy.BVS(n, value_size))
        present_func = CreateUninterpretedFunction((name or "map") + "_present", lambda n: claripy.BVS(n, 1))

        obj = self.state.memory.allocate_opaque(name)
        self.state.metadata.set(obj, Map(name, length, invariants, [], key_size, value_size, value_func, present_func))
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
            raise "Cannot add a key that might already be there!"

        map = self._get_map(obj)

        # Optimization: Filter out known-obsolete keys already
        new_items = [MapItem(i.key, claripy.If(i.key == key, value, i.value), claripy.If(i.key == key, claripy.BVV(1, 1), i.present)) for i in map.items if not i.key.structurally_match(key)] + \
                    [MapItem(key, value, claripy.BVV(1, 1))]
        self.state.metadata.set(obj, Map(map.name, map.length + 1, map.invariants, new_items, map.key_size, map.value_size, map.value_func, map.present_func), override=True)


    def remove(self, obj, key):
        # Requires the map to contain K.
        # Updates known items (K', V', P') into (K', V', P' and K != K')
        # Adds (K, V, false) to the known items.
        # Decrements the map length.

        if utils.can_be_false(self.state.solver, self.get(obj, key)[1]):
            raise "Cannot remove a key that might not be there!"

        map = self._get_map(obj)

        # Optimization: Filter out known-obsolete keys already
        bad_value = claripy.BVS("map_bad_value", map.value_size)
        new_items = [MapItem(i.key, claripy.If(i.key == key, bad_value, i.value), claripy.If(i.key == key, claripy.BVV(0, 1), i.present)) for i in map.items if not i.key.structurally_match(key)] + \
                    [MapItem(key, bad_value, claripy.BVV(0, 1))]
        self.state.metadata.set(obj, Map(map.name, map.length - 1, map.invariants, new_items, map.key_size, map.value_size, map.value_func, map.present_func), override=True)


    def get(self, obj, key, visited=None):
        # Let V = valuefunc(M)(K), P = presentfunc(M)(K)
        # Add (K, V, P) to the map's known items
        # Let V' =  ITE(K = K1, V1, ITE(K = K2, V2, ... V))
        # Let P' =  ITE(K = K1, P1, ITE(K = K2, P2, ... P))
        # Let L be the number of unique known keys in the map whose presence bit is set, including the newly-added item
        # Add L <= length(M) to the path constraint
        # Add invariant(M)(K, V', P') to the path constraint
        # Return (V', P')

        map = self._get_map(obj)
        LOG(self.state, "GET " + map.name + " " + str(key) + " (" + str(len(map.items)) + " items, " + str(len(self.state.solver.constraints)) + " constraints)")

        # Optimization: If the map is empty, the answer is always false
        if map.length.structurally_match(claripy.BVV(0, GhostMaps._length_size_in_bits)):
            LOGEND(self.state)
            return (claripy.BVS("map_bad_value", map.value_size), claripy.false)

        # Optimization: If the key exactly matches an item, answer that
        # (note: having to use definitely_true makes it expensive, but it allows for simpler reasoning later)
        for item in map.items:
            if key.structurally_match(item.key):
                LOGEND(self.state)
                return (item.value, item.present == 1)
        for item in map.items:
            if utils.definitely_true(self.state.solver, key == item.key):
                LOGEND(self.state)
                return (item.value, item.present == 1)

        # TODO IMPORTANT why can't we use BVS here? (though in order to get rid of UFs we'd need to get rid of "map_has" in inference...)
        #value = claripy.BVS("map_value", map.value_size)
        #present = claripy.BVS("map_present", 1)
        value = map.value_func(self.state, key)
        present = map.present_func(self.state, key)

        visited = visited or set([map.name])
        self.state.add_constraints(
            *[Implies(key == i.key, claripy.And(value == i.value, present == i.present)) for i in map.items],
            Implies(claripy.And(*[key != i.key for i in map.items]), claripy.And(*[inv(self.state, MapItem(key, value, present), visited) for inv in map.invariants])),
            self._known_length(obj) <= map.length
        )
        if not self.state.satisfiable():
            raise "Could not add constraints in ghost map get!?"

        # MUTATE the map!
        map.items.append(MapItem(key, value, present))

        LOGEND(self.state)
        return (value, present == 1)

    # TODO consider removing and using add + remove instead...
    def set(self, obj, key, value):
        # Requires the map to contain K.
        # Updates known items (K', V', P') into (K', ITE(K = K', V, V'), P' or K = K')
        # Adds (K, V, true) to the known items
        if utils.can_be_false(self.state.solver, self.get(obj, key)[1]):
            raise "Cannot set the value of a key that might not be there!"

        map = self._get_map(obj)

        # Optimization: Filter out known-obsolete keys already
        new_items = [MapItem(i.key, claripy.If(i.key == key, value, i.value), claripy.If(i.key == key, claripy.BVV(1, 1), i.present)) for i in map.items if not i.key.structurally_match(key)] + \
                    [MapItem(key, value, claripy.BVV(1, 1))]
        self.state.metadata.set(obj, Map(map.name, map.length, map.invariants, new_items, map.key_size, map.value_size, map.value_func, map.present_func), override=True)


    def forall(self, obj, pred):
        # Let L be the number of known items whose presence bit is set
        # Let K' be a fresh symbolic key and V' a fresh symbolic value
        # Let F = ((P1 => pred(K1, V1)) and (P2 => pred(K2, V2)) and (...) and ((L < length(M)) => (invariant(M)(K', V', true) => pred(K', V'))))
        # Add F => (P => pred(K, V)) to the map's invariant
        # Return F

        map = self._get_map(obj)
        LOG(self.state, "forall " + map.name + " (" + str(len(map.invariants)) + " invariants, " + str(len(self.state.solver.constraints)) + " constraints)")

        # Optimization: If the map is empty, the answer is always true
        if map.length.structurally_match(claripy.BVV(0, GhostMaps._length_size_in_bits)):
            LOGEND(self.state)
            return claripy.true

        known_len = self._known_length(obj)

        test_key = claripy.BVS("map_test_key", map.key_size)
        test_value = claripy.BVS("map_test_value", map.value_size)

        # Optimization: No need to even call the invariant if we're sure all items are known
        result = lambda st: claripy.And(*[Implies(i.present == 1, pred(i.key, i.value)) for i in map.items])
        if utils.can_be_false(self.state.solver, known_len == map.length):
            result = lambda st, old=result: claripy.And(
                old(st),
                Implies(
                    known_len < map.length,
                    Implies(
                        claripy.And(*[inv(st, MapItem(test_key, test_value, claripy.BVV(1, 1)), set([map.name])) for inv in map.invariants]), 
                        pred(test_key, test_value)
                    )
                )
            )

        # MUTATE the map!
        # Optimization: only if there's a chance it's useful, let's not needlessly complicate the invariant
        coco = self.state.copy()
        applied_result=result(coco)
        if utils.definitely_true(coco.solver, applied_result):
            LOGEND(self.state)
            return claripy.true
        if utils.definitely_false(coco.solver, applied_result):
            LOGEND(self.state)
            return claripy.false

        applied_result=result(self.state)
        map.invariants.append(lambda st, i, _: Implies(applied_result, Implies(i.present == 1, pred(i.key, i.value))))
        LOGEND(self.state)
        return applied_result


    # Implementation details used by other functions
    def _get_map(self, obj):
        # used by the invariant inference
        if isinstance(obj, Map):
            return obj
        return self.state.metadata.get(Map, obj)
    def _known_length(self, obj):
        map = self._get_map(obj)
        known_len = claripy.BVV(0, GhostMaps._length_size_in_bits)
        known_keys = []
        for item in map.items:
            key_is_new = claripy.And(*[item.key != k for k in known_keys])
            known_keys.append(item.key)
            known_len = known_len + claripy.If(claripy.And(key_is_new, item.present == 1), claripy.BVV(1, GhostMaps._length_size_in_bits), claripy.BVV(0, GhostMaps._length_size_in_bits))
        return known_len

    # Implementation details used during invariant inference
    # TODO remove these and use _get_map(...).xxx directly...
    def _known_items(self, obj): return self._get_map(obj).items
    def _invariants(self, obj): return self._get_map(obj).invariants
    def _value_func(self, obj): return self._get_map(obj).value_func
    def _present_func(self, obj): return self._get_map(obj).present_func


def maps_merge_across(states_to_merge, objs, ancestor_state):
    print("Cross-merge of maps starting. State count:", len(states_to_merge))

    results = [] # pairs: (ID, maps, lambda states, maps: returns None for no changes or maps to overwrite them)
    states = states_to_merge + [ancestor_state]

    # helper function to get only the items that are definitely in the map associated with the given obj in the given state
    def filter_present(state, obj):
        return [i for i in state.maps._known_items(obj) if utils.definitely_true(state.solver, i.present == 1)]

    # helper function to find FK or FV
    ancestor_variables = ancestor_state.solver.variables(claripy.And(*ancestor_state.solver.constraints))
    def find_f(o1, o2, sel1, sel2):
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

    # helper function to copy a map and add an invariant to the copy
    def add_invariant(map, inv):
        return Map(map.name, map.length, map.invariants + [inv], map.items, map.key_size, map.value_size, map.value_func, map.present_func)

    def xxx(visited, map, op, value_func):
        if map.name in visited or (map.name + op) in visited:
            return claripy.true
        visited.add(map.name + op)
        return value_func()

    # Optimization: Ignore maps that have not changed at all, e.g. those that are de facto readonly after initialization
    objs = [o for o in objs if any(not utils.structural_eq(ancestor_state.maps._get_map(o), st.maps._get_map(o)) for st in states)]

    # Copy the states to avoid polluting the real ones for the next steps of inference
    states = [s.copy() for s in states]

    # Invariant inference algorithm: if some property P holds in all states to merge and the ancestor state, optimistically assume it is part of the invariant
    for o1 in objs:
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
            #  if there exist functions FP, FK such that in all states, forall(M1, (K,V): FP(K,V) => get(M2, FK(K, V)) == (_, true)),
            #  then assume this is an invariant of M1 in the merged state.
            #  Additionally,
            #   if there exists a function FV such that in all states, forall(M1, (K,V): FP(K,V) => get(M2, FK(K, V)) == (FV(K, V), true)),
            #   then assume this is an invariant of M1 in the merged state.
            # TODO: a string ID is not really enough to guarantee the constraints are the same here...
            # We use maps directly to refer to the map state as it was in the ancestor, not during execution;
            # otherwise, get(M1, k) after remove(M2, k) might add has(M2, k) to the constraints, which is obviously false
            fk = find_f(o1, o2, lambda i: i.key, lambda i: i.key) \
              or find_f(o1, o2, lambda i: i.value, lambda i: i.key)
            fps = find_f_constants(o1, lambda i: i.value)
            for fp in fps:
                if fk and all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v, st=st, o2=o2, fp=fp, fk=fk: Implies(fp(MapItem(k, v, None)), st.maps.get(o2, fk(MapItem(k, v, None)))[1]))) for st in states):
                    log_item = MapItem(claripy.BVS("K", ancestor_state.maps.key_size(o1)), claripy.BVS("V", ancestor_state.maps.value_size(o1)), None)
                    print("Inferred: when", o1, "contains (K,V), if", fp(log_item), "then", o2, "contains", fk(log_item))
                    results.append(("cross-key", [o1, o2], lambda state, maps, fp=fp, fk=fk: [add_invariant(maps[0], lambda st, i, visited, maps=maps, fp=fp, fk=fk: xxx(visited, maps[1], "k", lambda maps=maps, fp=fp, fk=fk: Implies(i.present == 1, Implies(fp(i), st.maps.get(maps[1], fk(i), visited)[1])))), maps[1]]))
                    fv = find_f(o1, o2, lambda i: i.key, lambda i: i.value) \
                      or find_f(o1, o2, lambda i: i.value, lambda i: i.value)
                    if fv and all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v, st=st, o2=o2, fp=fp, fk=fk, fv=fv: Implies(fp(MapItem(k, v, None)), st.maps.get(o2, fk(MapItem(k, v, None)))[0] == fv(MapItem(k, v, None))))) for st in states):
                        print("          in addition, the value is", fv(log_item))
                        results.append(("cross-value", [o1, o2], lambda state, maps, fp=fp, fk=fk, fv=fv: [add_invariant(maps[0], lambda st, i, visited, maps=maps, fp=fp, fk=fk, fv=fv: xxx(visited, maps[1], "v", lambda maps=maps, fp=fp, fk=fk, fv=fv: Implies(i.present == 1, Implies(fp(i), st.maps.get(maps[1], fk(i), visited)[0] == fv(i))))), maps[1]]))
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
    if all(utils.structural_eq(ancestor_state.maps._get_map(obj), st.maps._get_map(obj)) for st in states_to_merge):
        print("Map", obj, "has not changed at all")
        return ancestor_state.maps._get_map(obj)

    # Oblivion algorithm: "forget" known items by integrating them into the unknown items invariant
    invariants = []
    # Step 1: invariant.
    # For each conjunction in the unknown items invariant,
    # for each known item in any state,
    #  if the conjunction may not hold on that item assuming the item is present,
    #  find constraints that do hold and add them as a disjunction to the conjunction.
    for conjunction in ancestor_state.maps._invariants(obj):
        for state in states_to_merge:
            for item in state.maps._known_items(obj):
                if utils.can_be_true(state.solver, claripy.And(item.present == 1, claripy.Not(conjunction(state, item, set())))):
                    constraints = claripy.And(*find_constraints(state, item.key), *find_constraints(state, item.value))
                    print("Item", item, "in map", obj, "does not comply with one invariant conjunction; adding disjunction", constraints)
                    conjunction = lambda st, i, visited, oldc=conjunction, oldi=item, cs=constraints: \
                                  claripy.Or(oldc(st, i, visited), cs.replace(oldi.key, i.key).replace(oldi.value, i.value))
        invariants.append(conjunction)

    # Step 2: length.
    # If the length may have changed in any state from the one in the ancestor state,
    # replace the length with a fresh symbol
    length = ancestor_state.maps.length(obj)
    for state in states_to_merge:
        if utils.can_be_false(state.solver, state.maps.length(obj) == length):
            print("Length of map", obj, " was changed; making it symbolic")
            length = claripy.BVS("map_length", GhostMaps._length_size_in_bits)
            break

    return Map(
        ancestor_state.maps._get_map(obj).name,
        length,
        invariants,
        ancestor_state.maps._known_items(obj),
        ancestor_state.maps.key_size(obj),
        ancestor_state.maps.value_size(obj),
        ancestor_state.maps._value_func(obj),
        ancestor_state.maps._present_func(obj)
    )