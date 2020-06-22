import angr
from angr.state_plugins.plugin import SimStatePlugin
import claripy
from recordclass import recordclass
from executors.binary.metadata import Metadata
import executors.binary.utils as utils
from collections import namedtuple
import itertools


# "length" is symbolic, and may be larger than len(items) if there are items that are not exactly known
# "invariants" is a conjunction of Boolean invariants on key/value pairs, represented as lambdas that take (state, key, value) and return an expression
# "items" contains exactly known items, which do not have to obey the invariants
# !!! "items" is a parameterless lambda returning a list - it allows maps to refer to previous ones' items,
#     so that invariants can be defined in terms of a specific map rather than whatever the map currently is
# "missing_value" is a placeholder indicating a missing value, that can be returned by get()
# "key_size" is the size of keys in bits, as a non-symbolic integer
Map = recordclass("Map", ["length", "invariants", "items", "missing_value", "key_size"])
# Items in a map can be redundant but not contradictory (i.e. there cannot be 2 items whose might be equal with values that might not be equal)
MapItem = namedtuple("MapItem", ["key", "value"])

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

        invariants = []

        missing_value = claripy.BVS("missing_value", value_size)

        if array_length is None:
            length = claripy.BVV(0, GhostMaps._length_size_in_bits)
        else:
            length = array_length
            invariants.append(lambda st, k, v: k.ULT(array_length) == (v != missing_value))

        if default_value is not None:
            invariants.append(lambda st, k, v: v == default_value)

        self.state.metadata.set(obj, Map(length, invariants, lambda: [], missing_value, key_size))
        return obj


    def length(self, obj):
        map = self.state.metadata.get(Map, obj)
        return map.length

    def value_size(self, obj):
        return self.missing_value(obj).size()
    
    def missing_value(self, obj):
        map = self.state.metadata.get(Map, obj)
        return map.missing_value


    def add(self, obj, key, value):
        if utils.can_be_true(self.state.solver, self.get(obj, key) != self.missing_value(obj)):
            raise angr.AngrExitError("Cannot add a key that might already be there!")

        map = self.state.metadata.get(Map, obj)

        self.state.add_constraints(value != map.missing_value)

        old_items = map.items
        new_items = lambda: old_items() + [MapItem(key, value)]
        self.state.metadata.set(obj, Map(map.length + 1, map.invariants, new_items, map.missing_value, map.key_size), override=True)


    def remove(self, obj, key):
        if utils.can_be_true(self.state.solver, self.get(obj, key) == self.missing_value(obj)):
            raise angr.AngrExitError("Cannot remove a key that might not be there!")

        map = self.state.metadata.get(Map, obj)

        new_items = lambda: [MapItem(item.key, claripy.If(item.key == key, map.missing_value, item.value)) for item in map.items()] + \
                            [MapItem(key, map.missing_value)]
        self.state.metadata.set(obj, Map(map.length - 1, map.invariants, new_items, map.missing_value, map.key_size), override=True)


    def get(self, obj, key):
        # backdoor used by invariant inference...
        if isinstance(obj, Map):
            map = obj
        else:
            map = self.state.metadata.get(Map, obj)

        # First, look up the item; if we know about it, just answer that for simplicity
        for item in map.items():
            if utils.definitely_true(self.state.solver, item.key == key):
                return item.value

        # If we don't have an item that matches the key, create one
        # for the item to be there, i.e. value != missing, we must have space
        known_len = claripy.BVV(0, GhostMaps._length_size_in_bits)
        for item in map.items():
            known_len = known_len + claripy.If(item.value == map.missing_value, claripy.BVV(0, GhostMaps._length_size_in_bits), claripy.BVV(1, GhostMaps._length_size_in_bits))
        new_item_value = self.state.solver.BVS("map_value", map.missing_value.size())
        item_constraints = [claripy.Or(new_item_value == map.missing_value, known_len < map.length)] + \
                           [inv(self.state, key, new_item_value) for inv in map.invariants]

        # Avoid adding a pointless "always missing" item, it makes reasoning more complicated
        if utils.definitely_true(self.state.solver, new_item_value == map.missing_value, extra_constraints=item_constraints):
            return map.missing_value

        self.state.add_constraints(*item_constraints)
        old_items = map.items
        # only time we actually MUTATE the map!
        map.items = lambda: old_items() + [MapItem(key, new_item_value)]

        # Now answer in terms of items
        value = map.missing_value
        for item in map.items():
            value = claripy.If(item.key == key, item.value, value)
        return value


    def set(self, obj, key, value):
        if utils.can_be_true(self.state.solver, self.get(obj, key) == self.missing_value(obj)):
            raise angr.AngrExitError("Cannot set the value of a key that might not be there!")

        map = self.state.metadata.get(Map, obj)

        self.state.add_constraints(value != map.missing_value)

        # While we allow duplicate items, let's try to avoid them to simplify human debugging
        new_items = lambda: [MapItem(item.key, claripy.If(item.key == key, value, item.value)) for item in map.items() if not key.structurally_match(item.key)] + \
                            [MapItem(key, value)]
        self.state.metadata.set(obj, Map(map.length, map.invariants, new_items, map.missing_value, map.key_size), override=True)


    def forall(self, obj, pred):
        map = self.state.metadata.get(Map, obj)

        known_len = claripy.BVV(0, GhostMaps._length_size_in_bits)
        for item in map.items():
            known_len = known_len + claripy.If(item.value == map.missing_value, claripy.BVV(0, GhostMaps._length_size_in_bits), claripy.BVV(1, GhostMaps._length_size_in_bits))

        test_key = claripy.BVS("map_test_key", map.key_size)
        test_value = claripy.BVS("map_test_value", map.missing_value.size())
        return claripy.And(
            # if there are unknown items, the invariants must imply the predicate
            claripy.Or(
                known_len == map.length,
                claripy.Or(
                    claripy.Not(claripy.And(*[inv(self.state, test_key, test_value) for inv in map.invariants])),
                    pred(test_key, test_value)
                )
            ),
            *[claripy.Or(item.value == map.missing_value, pred(item.key, item.value)) for item in map.items()]
        )


    def keep_only_those_in_state(self, other_state):
        other_objs = [obj for (obj, _) in other_state.metadata.get_all(Map)]
        for (obj, _) in self.state.metadata.get_all(Map):
            if all(o is not obj for o in other_objs):
                self.state.metadata.remove(Map, obj)


# Returns a list of ([objs], lambda) tuples where lambda takes (state, [objs], [maps]) and returns [new_maps]
def pre_process_maps(maps_by_obj, states):
    def map_of_obj(o, m_b_o):
        return next(m for (o2, m) in m_b_o if o2 is o) # yay for O(way too much) algorithms!
    objs = [o for (o, m) in maps_by_obj[0]]

    # sanity check...
    for n in range(1, len(states)):
        nobjs = [o for (o, m) in maps_by_obj[n]]
        if len(objs) != len(nobjs):
            raise angr.AngrExitError("Pre process map assertion failure; all states should have the same number of objs")
        for o in objs:
            if all(o is not o2 for o2 in nobjs):
                raise angr.AngrExitError("Pre process map assertion failure; all objs do not match (or maybe they only match with a solver assert...)")

    result = []
    # 1. If length_1 >= length_2 in all states, assume this will hold
    # ughhhh why doesn't python have custom dictionary comparers that would make this soooo much easier/faster :(
    for o1 in objs:
        for o2 in objs:
            if o1 is o2: continue

            def postproc_uge(st, objs, maps, extra):
                st.add_constraints(maps[0].length.UGE(maps[1].length))
                return maps
            if all(utils.definitely_true(states[n].solver, map_of_obj(o1, maps_by_obj[n]).length.UGE(map_of_obj(o2, maps_by_obj[n]).length)) for n in range(len(states))):
                result.append(([o1, o2], postproc_uge, None))

    # 2. Linked invariants
    # first, check that all maps have 0 / 1 items
    def present_items(m):
        return [i for i in m.items() if not i.value.structurally_match(m.missing_value)]
    bad_map = next((m for m_b_o in maps_by_obj for (o, m) in m_b_o if len(present_items(m)) > 1), None)
    if bad_map is not None:
        print("Linked invariant inference gave up. This is not a failure, but if something fails later it might be why...")
        return result
    def get_shape(og_obj, cand_obj, og_selector, cand_selector, strict=True):
        replacement = None
        shape = None
        constant = None
        constant_length = None
        for (state, og_map, cand_map) in [(states[n], map_of_obj(og_obj, maps_by_obj[n]), map_of_obj(cand_obj, maps_by_obj[n])) for n in range(len(states))]:
            og_items = present_items(og_map)
            cand_items = present_items(cand_map)
            if len(og_items) == 0:
                continue
            if len(og_items) != 1 or len(cand_items) != 1:
                raise angr.AngrExitError("This should never happen, we checked earlier... sanity test")
            og_val = og_selector(og_items[0])
            cand_val = cand_selector(cand_items[0])
            if shape is None and constant is None:
                replacement = state.solver.BVS('shape_replacement', og_val.length)
                if strict and not cand_val.structurally_match(og_val) and next((c for c in cand_val.children_asts() if c.structurally_match(og_val)), None) is None: # children_asts doesn't contain root
                    return None # it doesn't even contain og_val
                maybe_constant = state.solver.eval_upto(cand_val, 2, cast_to=int) if not strict else []
                if len(maybe_constant) == 1:
                    constant = maybe_constant[0] # it's a constant! easy peasy!
                    constant_length = cand_val.length
                else:
                    if og_val.length != cand_val.length:
                        return None # mismatched sizes - but only check here, if it's a constant we're good
                    shape = cand_val.replace(og_val, replacement)
            else:
               if constant is None:
                   if not shape.structurally_match(cand_val.replace(og_val, replacement)):
                      return None
               else:
                   maybe_constant = state.solver.eval_upto(cand_val, 2, cast_to=int) if not strict else []
                   if len(maybe_constant) != 1 or maybe_constant[0] != constant:
                       return None
        if constant is not None:
            return (states[0].solver.BVV(constant, constant_length), replacement) # replacement won't really be used but we have to return something...
        if shape is not None: # items were always 0-len
            return (shape, replacement)
        return None
    # apologies to future me who might have to maintain this, as well as to anyone who has to read it! it *is* pretty straightforward, just long
    def postproc_valinkey(state, objs, maps, extra):
        m = maps[0]
        (shape, replacement) = extra
        return (Map(m.length, m.invariants + [lambda st, k, v: claripy.Or(v == m.missing_value, st.maps.get(maps[1], shape.replace(replacement, v)) != maps[1].missing_value)], m.items, m.missing_value, m.key_size), maps[1])
    def postproc_valinkeykeyinval(state, objs, maps, extra):
        m = maps[0]
        ((shape1, replacement1), (shape2, replacement2)) = extra
        return (Map(m.length, m.invariants + [lambda st, k, v: claripy.Or(v == m.missing_value, st.maps.get(maps[1], shape1.replace(replacement1, v)) == shape2.replace(replacement2, k))], m.items, m.missing_value, m.key_size), maps[1])
    def postproc_keyinkey(state, objs, maps, extra):
        m = maps[0]
        (shape, replacement) = extra
        return (Map(m.length, m.invariants + [lambda st, k, v: claripy.Or(v == m.missing_value, st.maps.get(maps[1], shape.replace(replacement, k)) != maps[1].missing_value)], m.items, m.missing_value, m.key_size), maps[1])
    def postproc_keyinkeyvalinval(state, objs, maps, extra):
        m = maps[0]
        ((shape1, replacement1), (shape2, replacement2)) = extra
        return (Map(m.length, m.invariants + [lambda st, k, v: claripy.Or(v == m.missing_value, st.maps.get(maps[1], shape1.replace(replacement1, k)) == shape2.replace(replacement2, v))], m.items, m.missing_value, m.key_size), maps[1])
    # find "matching" maps, i.e. maps whose len(items) is the same in all states as len(our map's items)
    # ideally we should create equivalence classes once, instead of doing this for each map; oh well
    matching_objs_by_obj = [(obj, [o for (o, m) in maps_by_obj[0] if o is not obj and all(len(present_items(m1)) == len(present_items(m2)) for (m1, m2) in [(map_of_obj(obj, m_b_o), map_of_obj(o, m_b_o)) for m_b_o in maps_by_obj])]) for (obj, map) in maps_by_obj[0]]
    already_done = [] # avoid invariant loops of map1.get -> map2.get -> map1.get...
    matching_objs_by_obj = sorted(matching_objs_by_obj, reverse=True, key=lambda pair: len(pair[1]))
    for (obj, matching_objs) in matching_objs_by_obj:
        already_done.append(obj)
        for matching_obj in matching_objs:
            if next((o for o in already_done if o.structurally_match(matching_obj)), None) is not None: # don't incur claripy's wrath by using 'in' or 'any(...)' which calls ==
                continue
            val_in_key = get_shape(obj, matching_obj, lambda i: i.value, lambda i: i.key)
            if val_in_key is not None:
                # val could also be in val but that'd be weird, since it's already in key
                key_in_val = get_shape(obj, matching_obj, lambda i: i.key, lambda i: i.value, strict=False) # not strict; a constant is fine...
                result.append(([obj, matching_obj], postproc_valinkey, val_in_key))
                if key_in_val is not None:
                    result.append(([obj, matching_obj], postproc_valinkeykeyinval, (val_in_key, key_in_val)))
            else:
                key_in_key = get_shape(obj, matching_obj, lambda i: i.key, lambda i: i.key)
                if key_in_key is not None:
                    result.append(([obj, matching_obj], postproc_keyinkey, key_in_key))
                    # key could also be in val but that'd be weird, since it's already in key
                    val_in_val = get_shape(obj, matching_obj, lambda i: i.value, lambda i: i.value, strict=False)
                    if val_in_val is not None:
                        result.append(([obj, matching_obj], postproc_keyinkeyvalinval, (key_in_key, val_in_val)))
    return result

def merge_maps(maps, states):
    def get_constraint(state, expr):
        maybe_constant = state.solver.eval_upto(expr, 2)
        if len(maybe_constant) == 1:
            return expr == maybe_constant[0]
        # Might miss a lot of stuff but will do for now, this is sound since having overly lax invariants can lead to nonexistent paths but not to ignored ones
        return claripy.And(*[cons for cons in state.solver.constraints if next((c for c in cons.children_asts() if c.structurally_match(expr)), None) is not None])

    map = maps[0]
    state = states[0]
    if any(m.invariants != map.invariants or not m.missing_value.structurally_match(map.missing_value) or m.key_size != map.key_size for m in maps[1:]):
        raise angr.AngrExitError("Maps do not match!")

    invariants = []
    has_changed = False

    # If any invariant does not apply to an item, add an OR so it does
    # Using "== item.key/value" is likely pointless since their constraints will no longer exist after the merge because they refer to variables within an iteration
    # Instead, try to collect constraints about the key/value
    for inv in map.invariants + ([lambda st, k, v: claripy.false] if len(map.invariants) == 0 else []):
        alternatives = []
        for (m, st) in zip(maps, states):
            for item in m.items():
                if utils.can_be_true(st.solver, item.value != m.missing_value) and utils.definitely_false(st.solver, inv(st, item.key, item.value)):
                    has_changed = True
                    key_cons = get_constraint(st, item.key)
                    value_cons = get_constraint(st, item.value)
                    real_item_key = item.key # avoid capture
                    real_item_value = item.value
                    alternatives.append(lambda st, k, v: claripy.And(key_cons.replace(real_item_key, k), value_cons.replace(real_item_value, v)))
        inv_copy = inv # avoid capture
        invariants.append(lambda st, k, v: claripy.Or(inv_copy(st, k, v), *[i(st, k, v) for i in alternatives]))

    # If the length differs across states, make it unconstrained and add an unknown element to the invariants
    result_length = map.length
    for m in maps[1:]:
        if not m.length.structurally_match(map.length):
            has_changed = True
            result_length = states[0].solver.BVS("map_merged_length", GhostMaps._length_size_in_bits)
            invariants.append(lambda st, k, v: claripy.Or(claripy.BVS("map_has", 1) == 0, v != m.missing_value)) # note: BoolS was behaving oddly once, let's stay in the BVs...
            break

    if has_changed:
        GhostMaps.changed_last_merge = True
    return Map(result_length, invariants, lambda: [], map.missing_value, map.key_size)

def post_process_maps(state, result):
    if not GhostMaps.changed_last_merge:
        return
    for (objs, lam, extra) in result:
        maps = [state.metadata.get(Map, o) for o in objs]
        new_maps = lam(state, objs, maps, extra)
        for (o, m) in zip(objs, new_maps):
            state.metadata.set(o, m, override=True)
