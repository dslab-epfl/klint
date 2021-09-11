from angr.state_plugins.plugin import SimStatePlugin
import claripy
import copy
import datetime
import itertools
import os
import threading
import queue
from collections import namedtuple
from enum import Enum

from kalm import utils
from klint import statistics

# NOTE: All optimizations should be periodically re-evaluated, since adding new features may make them pointless or even harmful
#       (e.g., making solver calls that are unnecessary due to some other change)

# TODO through deepcopy we should be able to refer directly to maps, right? without the obj indirection because the map would be the updated one after copy...

        # TODO: I wonder if it makes sense to refactor as "map" and "map layer" since the layer can only have stuff on known items?


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


# Helper function to make expressions clearer
def Implies(a, b):
    return ~a | b

MapMeta = namedtuple("MapMeta", ["name", "key_size", "value_size"]) # sizes are ints (not BVs!), in bits
MapItem = namedtuple("MapItem", ["key", "value", "present"])

# TODO it is weird that MapHas/MapGet take in an obj to pass to state.maps[...] instead of a map... can we fix this? might require major refactor of invariant inf
#      Then we can take only the solver as parameter everywhere, not the entire state
#      And maybe even move the solver optimizations part (constants and such) to the plugin itself instead of the maps?

# TODO: Any way we can remove ITEs completely here? out of curiosity...

# MapHas/MapGet *must* be used whenever doing anything inside of a forall... otherwise bad stuff might happen

# value=None -> returns whether the map has the key; value!=None -> also checks whether the map has exactly that value for the key
def MapHas(map, key, value=None, version=None):
    return claripy.ast.Bool("MapHas", [map, key, value, version])

def MapGet(map, key, value_size, version=None):
    return claripy.ast.BV("MapGet", [map, key, version], length=value_size)

# Allow us to operate on these within expressions using replace_dict's leaf_operation parameter
claripy.operations.leaf_operations.add("MapHas")
claripy.operations.leaf_operations.add("MapGet")

# note: replace_dict must have AST .cache_key as keys
def eval_map_ast_core(expr, replace_dict, has_handler, get_handler):
    def replacer(leaf):
        if not isinstance(leaf, claripy.ast.Base):
            return leaf
        if leaf.op == "MapHas":
            return has_handler(leaf, replacer)
        if leaf.op == "MapGet":
            return get_handler(leaf, replacer)
        if leaf.op in claripy.operations.leaf_operations:
            return replace_dict.get(leaf.cache_key, leaf)
        return leaf.replace_dict(replace_dict, leaf_operation=replacer)
    return replacer(expr)

def freeze_map_ast_versions(state, expr):
    def map_handler(ast, replacer):
        map = ast.args[0] if isinstance(ast.args[0], Map) else state.maps[ast.args[0]]
        return ast.make_like(ast.op, [replacer(a) for a in ast.args[0:len(ast.args)-1]] + [map.version()])
    return eval_map_ast_core(expr, {}, map_handler, map_handler)

def eval_map_ast(state, expr, replace_dict={}, condition=claripy.true):
    def has_handler(ast, replacer):
        map = ast.args[0] if isinstance(ast.args[0], Map) else state.maps[ast.args[0]]
        replaced_key = replacer(ast.args[1])
        replaced_value = replacer(ast.args[2])
        if replaced_value is None:
            return map.get(state, replaced_key, condition=condition, version=ast.args[2])[1]
        result = map.get(state, replaced_key, conditioned_value=replaced_value, condition=condition, version=ast.args[3])
        return result[1] & (result[0] == replaced_value)
    def get_handler(ast, replacer):
        map = ast.args[0] if isinstance(ast.args[0], Map) else state.maps[ast.args[0]]
        replaced_key = replacer(ast.args[1])
        return map.get(state, replaced_key, condition=condition, version=ast.args[2])[0]
    return eval_map_ast_core(expr, replace_dict, has_handler, get_handler)


class MapInvariant:
    @staticmethod
    def new(state, meta, expr_factory):
        key = claripy.BVS("KEY", meta.key_size, explicit_name=True)
        value = claripy.BVS("VALUE", meta.value_size, explicit_name=True)
        present = claripy.BoolS("PRESENT", explicit_name=True)
        expr = expr_factory(MapItem(key, value, present))
        expr = freeze_map_ast_versions(state, expr)
        return MapInvariant(expr, key, value, present)

    def __init__(self, expr, key, value, present):
        self.expr = expr
        self.key = key
        self.value = value
        self.present = present

    def __call__(self, state, item, condition=claripy.true):
        replace_dict = {self.key.cache_key: item.key, self.value.cache_key: item.value, self.present.cache_key: item.present}
        return eval_map_ast(state, self.expr, replace_dict=replace_dict, condition=item.present & condition)

    def __eq__(self, other):
        return self.expr.structurally_match(other.expr)

    def __repr__(self):
        return str(self.expr)

    def with_expr(self, expr_factory):
        return MapInvariant(expr_factory(self.expr, MapItem(self.key, self.value, self.present)), self.key, self.value, self.present)

    def with_latest_map_versions(self, state):
        return MapInvariant(freeze_map_ast_versions(state, self.expr), self.key, self.value, self.present)


class Map:
    # === Public API ===

    @staticmethod
    def new(state, key_size, value_size, name, _invariants=None, _length=None, _exact_name=False, _name_counter=[0]): # use a list for the counter as a byref equivalent
        def to_int(n, name):
            if isinstance(n, int):
                return n
            if n.op == "BVV":
                return n.args[0]
            raise Exception(name + " cannot be symbolic")

        key_size = to_int(key_size, "key_size")
        value_size = to_int(value_size, "value_size")

        if not _exact_name:
            name = name + "_" + str(_name_counter[0])
            _name_counter[0] = _name_counter[0] + 1

        assert (_length is None) == (_invariants is None), "otherwise we'll add ~P as inv which makes no sense"

        if _length is None:
            _length = claripy.BVV(0, state.sizes.size_t)
        if isinstance(_length, int):
            _length = claripy.BVV(_length, state.sizes.size_t)

        result = Map(MapMeta(name, key_size, value_size), _length, [], [])
        if _invariants is None:
            # we have to have >0 invariants
            result.add_invariant_conjunction(state, lambda i: ~i.present)
        else:
            for inv in _invariants:
                result.add_invariant_conjunction(state, inv)
        return result

    @staticmethod
    def new_array(state, key_size, value_size, length, name):
        return Map.new(state, key_size, value_size, name, _invariants=[lambda i: (i.key < length) == i.present], _length=length)

    def length(self):
        return self._length

    def get(self, state, key, conditioned_value=None, condition=claripy.true, version=None):
        if version is not None:
            to_call = self
            self_ver = self.version()
            while version < self_ver:
                to_call = to_call._previous
                version = version + 1
            return to_call.get(state, key, conditioned_value=conditioned_value, condition=condition)

        LOG(state, "GET " + self.meta.name + f" version: {version} " + (" key: " + str(key)) + ((" value: " + str(conditioned_value)) if conditioned_value is not None else "") + (" cond: " + str(condition)))

        # Optimization: If the map is empty, the answer is always false
        if self.is_definitely_empty():
            LOGEND(state)
            return (claripy.BVS(self.meta.name + "_bad_value", self.meta.value_size), claripy.false)

        # If the map contains an item (K', V', P') such that K' = K, then return (V', P') [assuming the condition]
        known_items = self.known_items()
        matching_item = utils.get_exact_match(state.solver, key, known_items + [self._unknown_item], assumption=condition, selector=lambda i: i.key)
        if matching_item is not None:
            LOGEND(state)
            return (matching_item.value, matching_item.present)

        # Let V be a fresh symbolic value [using the hint]
        value = claripy.BVS(self.meta.name + "_value", self.meta.value_size)
        if conditioned_value is not None:
            state.solver.add(Implies(condition, value == conditioned_value))

        # Let P be a fresh symbolic presence bit
        present = claripy.BoolS(self.meta.name + "_present")

        # Let UK be And(K != K') for each key K' in the map's known items
        unknown = claripy.And(*[key != i.key for i in known_items])

        # MUTATE the map's known items by adding (K, V, P)
        # This must happen now; calling the invariant later might cause recursion which needs the item to be in there to stop
        self.add_item(MapItem(key, value, present))

        state.solver.add(
            # Add K = K' => (V = V' and P = P') to the path constraint for each existing known item (K', V', P') in the map,
            *[Implies(key == i.key, (value == i.value) & (present == i.present)) for i in known_items + [self._unknown_item]],
            # Add UK => invariant(M)(K', V', P') to the path constraint [conditioned]
            *[Implies(unknown, inv(state, MapItem(key, value, present), condition=condition)) for inv in self.invariant_conjunctions()],
            # Add L <= length(M)
            self.is_not_overfull(state)
        )

        # Return (V, P)
        LOGEND(state)
        return (value, present)

    def set(self, state, key, value):
        # Let P be get(M, K) != None
        (_, present) = self.get(state, key)

        # Return a new map with:
        #   ITE(P, 0, 1) added to the map length.
        #   Each known item (K', V', P') updated to (K', ITE(K = K', V', V), ITE(K = K', true, P'))
        #   (K, V, true) added to the known items
        return self.with_item_layer(
            item=MapItem(key, value, claripy.true),
            length_change=claripy.If(present, claripy.BVV(0, self.length().size()), claripy.BVV(1, self.length().size())),
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
        return self.with_item_layer(
            item=MapItem(key, value, claripy.false),
            length_change=claripy.If(present, claripy.BVV(-1, self.length().size()), claripy.BVV(0, self.length().size())),
        )

    def forall(self, state, pred):
        if not isinstance(pred, MapInvariant):
            pred = MapInvariant.new(state, self.meta, (lambda i, old_pred=pred: Implies(i.present, old_pred(i.key, i.value))))

        LOG(state, "forall " + self.meta.name + "  " + str(pred))

        # Optimization: If the map is empty, the answer is always true
        if self.is_definitely_empty():
            return claripy.true

        known_items = self.known_items()
        known_items_result = claripy.And(*[pred(state, i) for i in known_items])

        unknown_is_not_known = claripy.And(*[self._unknown_item.key != i.key for i in known_items])
        unknown_items_result = Implies(self.is_not_overfull(state), Implies(unknown_is_not_known, pred(state, self._unknown_item)))
        # TODO try with just (since we don't really need the weird length=1 case)
        #unknown_items_result = Implies(unknown_is_not_known, pred(state, self._unknown_item))

        result = claripy.BoolS(self.meta.name + "_forall")
        state.solver.add(result == claripy.And(known_items_result, unknown_items_result))
        self.add_invariant_conjunction(state, pred.with_expr(lambda e, i: Implies(result, e)))
        LOGEND(state)
        return result

    # === Merging ===
    # Two-phase merging, so that we avoid spending lots of (solver) time on a merge only to realize the very next map can't be merged and the effort was wasted

    def can_merge(self, others):
        if all(utils.structural_eq(self, o) for o in others):
            return True
        if any(o.meta.key_size != self.meta.key_size or o.meta.value_size != self.meta.value_size for o in others):
            #print("Different meta")
            return False
        if any(not utils.structural_eq(self._invariants, o._invariants) for o in others):
            #print("Different invariants")
            return False
        self_ver = self.version()
        if any(o.version() != self_ver for o in others):
            #print("Different versions")
            return False
        if self_ver > 0 and not self._previous.can_merge([o._previous for o in others]):
            #print("Previous cannot be merged")
            return False
        max_to_add = 0
        for o in others:
            (_, _, to_add) = utils.structural_diff(self._known_items, o._known_items)
            max_to_add = max(max_to_add, len(to_add))
        if max_to_add > 5:
            #print("too many items to add")
            return False
        return True

    # This assumes the solvers have already been merged
    def merge(self, state, others, other_states, merge_conditions):
        if all(utils.structural_eq(self, o) for o in others):
            return
        for (o, mc) in zip(others, merge_conditions[1:]):
            (only_left, both, only_right) = utils.structural_diff(self._known_items, o._known_items)
            # Items that were only here are subject to the invariant if the merge condition holds
            for i in only_left:
                state.solver.add(*[Implies(mc, inv(state, i)) for inv in self.invariant_conjunctions()])
            # Other items must be those of the other state if the merge condition holds
            for i in both + only_right:
                (v, p) = self.get(state, i.key)
                state.solver.add(Implies(mc, (v == i.value) & (p == i.present)))
        # Basic map invariants have to hold no matter what
        for (n, it) in enumerate(self._known_items):
            state.solver.add(*[Implies(i.key == oi.key, (i.value == oi.value) & (i.present == oi.present)) for oi in self._known_items[(n+1):] + [self._unknown_item]])
        state.solver.add(self.is_not_overfull(state))
        if self._previous is not None:
            self._previous.merge(state, [o._previous for o in others], other_states, merge_conditions)

    # === Private API, also used by invariant inference ===
    # TODO sort out what's actually private and not; verif also uses stuff...

    def __init__(self, meta, length, invariants, known_items, _previous=None, _unknown_item=None, _layer_item=None):
        # "length" is symbolic, and may be larger than len(items) if there are items that are not exactly known
        # "invariants" is a list of conjunctions that represents unknown items: each is a lambda that takes (state, item) and returns a Boolean expression
        # "items" contains exactly known items, which do not have to obey the invariants
        self.meta = meta
        self._length = length
        self._invariants = invariants
        self._known_items = known_items
        self._previous = _previous
        if _unknown_item is None:
            _unknown_item = MapItem(
                claripy.BVS(self.meta.name + "_unknown_key", self.meta.key_size),
                claripy.BVS(self.meta.name + "_unknown_value", self.meta.value_size),
                claripy.BoolS(self.meta.name + "_unknown_present")
            )
        self._unknown_item = _unknown_item
        self._layer_item = _layer_item

    def version(self):
        if self._previous is None: return 0
        else: return 1 + self._previous.version()

    def oldest_version(self):
        if self._previous is None: return self
        return self._previous.oldest_version()

    def invariant_conjunctions(self):
        if self._previous is None:
            return self._invariants.copy()
        return self._previous.invariant_conjunctions()

    def add_invariant_conjunction(self, state, inv):
        if not isinstance(inv, MapInvariant): # TODO we really need types to avoid that sort of thing
            inv = MapInvariant.new(state, self.meta, inv)
        if self._previous is None:
            state.solver.add(inv(state, self._unknown_item))
            self._invariants.append(inv)
        else:
            self._previous.add_invariant_conjunction(state, inv)

    def havoced(self, state, length, invs):
        return Map(
            self.meta,
            length,
            [MapInvariant.new(state, self.meta, inv) for inv in invs], # no invariants yet
            [] # no known items
        )

    def known_items(self, _exclude_get=False):
        if _exclude_get == True and self._previous is None:
            return []

        result = self._known_items.copy()
        if self._previous is not None:
            assert self._layer_item is not None
            result = result + [
                MapItem(i.key, claripy.If(i.key == self._layer_item.key, self._layer_item.value, i.value), claripy.If(i.key == self._layer_item.key, self._layer_item.present, i.present))
                for i in self._previous.known_items(_exclude_get=_exclude_get)
                if not i.key.structurally_match(self._layer_item.key)
            ]
        return result

    def add_item(self, item):
        if self._previous is None:
            self._known_items.append(item)
        else:
            self._previous.add_item(item)

    # TODO get rid of this unsafe thing if we can...
    def with_item_layer(self, item, length_change):
        return Map(
            self.meta,
            self._length + length_change,
            [], # no extra invariants, just use the ones in _previous
            [item],
            _previous=self,
            _unknown_item=self._unknown_item,
            _layer_item=item
        )

    def relax(self):
        return Map(
            self.meta,
            claripy.BVS(self.meta.name + "_length", self._length.size()),
            [], # no invariants yet
            [] # no known items
        )

    def is_definitely_empty(self):
        l = self.length()
        return l.structurally_match(claripy.BVV(0, l.size()))

    def is_not_overfull(self, state):
        l = self.length()
        known_items = self.known_items()

        # Optimization: If the map length is concrete and there are definitely not too many items, don't even compute the known length
        if utils.definitely_true(state.solver, len(known_items) <= l):
            return claripy.true
        #print("overfull? rip=", state.regs.rip, " minlen=", state.solver.min(l), " actlen=", len(known_items), " items=", [i.key for i in known_items])

        known_len = claripy.BVV(0, l.size())
        known_keys = []
        for item in known_items:
            key_is_new = claripy.And(*[item.key != k for k in known_keys])
            known_keys.append(item.key)
            known_len = known_len + claripy.If(key_is_new & item.present, claripy.BVV(1, l.size()), claripy.BVV(0, l.size()))
        return known_len <= l

    def __copy__(self):
        return self.__deepcopy__({})

    def __deepcopy__(self, memo):
        result = Map(
            self.meta, # immutable
            self._length, # immutable
            copy.copy(self._invariants), # contents are immutable
            copy.copy(self._known_items), # contents are immutable
            copy.deepcopy(self._previous, memo),
            self._unknown_item, # immutable
            self._layer_item # immutable
        )
        memo[id(self)] = result
        return result

    def __repr__(self):
        return f"<Map {self.meta.name} v{self.version()}>"

    def _asdict(self): # pretend we are a namedtuple so functions that expect one will work (e.g. utils.structural_eq)
        return {'meta': self.meta, '_length': self._length, '_invariants': self._invariants, '_known_items': self._known_items, '_previous': self._previous, '_unknown_item': self._unknown_item, '_layer_item': self._layer_item}


class GhostMapsPlugin(SimStatePlugin):
    # === Public API ===

    def new(self, key_size, value_size, name, _length=None, _invariants=None): # TODO new_havoced instead of _length/_invariants?
        obj = claripy.BVS(name, self.state.sizes.ptr)
        self[obj] = Map.new(self.state, key_size, value_size, name, _length=_length, _invariants=_invariants)
        return obj

    def new_array(self, key_size, value_size, length, name, obj=None): # obj so we can create arrays at existing points for BPF... (in general the whole GhostMapsPlugin API is dubious)
        if obj is None:
            obj = claripy.BVS(name, self.state.sizes.ptr)
        self[obj] = Map.new_array(self.state, key_size, value_size, length, name)
        return obj

    def length(self, obj):
        return self[obj].length()

    def key_size(self, obj):
        return self[obj].meta.key_size

    def value_size(self, obj):
        return self[obj].meta.value_size

    def get(self, obj, key, conditioned_value=None, condition=claripy.true, version=None):
        return self[obj].get(self.state, key, conditioned_value=conditioned_value, condition=condition, version=version)

    def set(self, obj, key, value):
        self[obj] = self[obj].set(self.state, key, value)

    def remove(self, obj, key):
        self[obj] = self[obj].remove(self.state, key)

    def forall(self, obj, pred):
        return self[obj].forall(self.state, pred)

    # === Havocing, not meant for general use ===

    def UNSAFE_havoc(self, obj, length, invs):
        self[obj] = self[obj].havoced(self.state, length, invs)

    # === Import and Export ===

    def get_all(self):
        return [(obj.ast, m) for (obj, m) in self._maps.items()]

    # === Private API, including for invariant inference ===

    def __getitem__(self, obj):
        return self._maps[obj.cache_key]

    def __setitem__(self, obj, map):
        self._maps[obj.cache_key] = map

    # === Angr stuff ===

    def __init__(self, _maps={}):
        SimStatePlugin.__init__(self)
        self._maps = _maps

    @SimStatePlugin.memo
    def copy(self, memo):
        return GhostMapsPlugin(_maps={k: copy.deepcopy(v, memo) for (k, v) in self._maps.items()}) # no need to deepcopy the keys

    def can_merge(self, others):
        if any(len(self._maps) != len(o._maps) for o in others):
            return False
        for (k, v) in self._maps.items():
            if any(k not in o._maps for o in others):
                return False
            if not v.can_merge([o._maps[k] for o in others]):
                return False
        return True

    def merge(self, others, merge_conditions, common_ancestor=None):
        for (k, v) in self._maps.items():
            v.merge(self.state, [o._maps[k] for o in others], [o.state for o in others], merge_conditions)
        return True



# === Invariant inference ===

# Get all variables from a set of states that have the same maps
def get_variables(states):
    result = set(states[0].solver.variables(claripy.And(*states[0].solver.constraints)))
    for st in states[1:]:
        result.intersection_update(st.solver.variables(claripy.And(*st.solver.constraints)))
    for (_, m) in states[0].maps.get_all():
        result = result - m._unknown_item.key.variables
        result = result - m._unknown_item.value.variables
        result = result - m._unknown_item.present.variables
    return result

# Find constraints that hold on an expression in a state
def find_constraints(state, expr, replacement, ancestor_variables):
    # If the expression is constant or constrained to be, return that
    const = utils.get_if_constant(state.solver, expr)
    if const is not None:
        return [replacement == const]
    # Otherwise, find constraints that contain the expression, but ignore those that also contain variables not in the ancestor
    # This might miss stuff due to transitive constraints,
    # but it's sound since having overly lax invariants can only over-approximate
    expr_vars = state.solver.variables(expr)
    results = []
    for constr in state.solver.constraints:
        constr_vars = state.solver.variables(constr)
        if not constr.replace(expr, replacement).structurally_match(constr) and constr_vars.difference(expr_vars).issubset(ancestor_variables):
            results.append(constr.replace(expr, replacement))
    # Also, if the item is always 0 in places, remember that.
    # Or at least remember the beginning, that's enough for a prototype.
    # This is because some programmers use variables that are too wide, e.g. their skeleton has the device as an u16 but they cast to an u32
    if expr.op == "Concat" and expr.args[0].structurally_match(claripy.BVV(0, expr.args[0].size())):
        results.append(replacement[expr.size()-1:expr.size()-expr.args[0].size()] == 0)
    return results

# "Flatten" a map's items into invariants, returning a (changed, new_invariants) tuple
def flatten_items(obj, states, ancestor_states, ancestor_variables):
    changed = False
    invariant_conjs = []
    for conjunction in ancestor_states[0].maps[obj].invariant_conjunctions():
        for state in states:
            # TODO can we get rid of _exclude_get entirely?
            for item in state.maps[obj].known_items(_exclude_get=True):
                conj = conjunction.with_latest_map_versions(state)(state, item)
                if utils.can_be_false(state.solver, Implies(item.present, conj)):
                    changed = True
                    conjunction = conjunction.with_expr(
                        lambda e, i, oldi=item, state=state: e | claripy.And(*find_constraints(state, oldi.key, i.key, ancestor_variables), *find_constraints(state, oldi.value, i.value, ancestor_variables))
                    )
                    print("Item", item, "in map", obj, "does not comply with invariant conjunction", conj, "; it is now", conjunction)
        invariant_conjs.append(conjunction)
    return (changed, invariant_conjs)


# Get length-related invariants on a map
def get_length_invariants(obj, relevant_objs, states, ancestor_states):
    if all(utils.definitely_true(st.solver, st.maps.length(obj) == ancestor_states[0].maps.length(obj)) for st in states):
        # No changes
        return None
    result = []
    for other_obj in relevant_objs:
        # Not the map itself
        if other_obj is obj: continue
        # Not maps that never changed in a state in which the map changed
        if all(st.maps[obj].version() == ancestor_states[0].maps[obj].version() or st.maps[other_obj].version() == ancestor_states[0].maps[other_obj].version() for st in states): continue
        # Try everything else for an <= length relationship
        inv = lambda st, obj=obj, other_obj=other_obj: st.maps.length(obj) <= st.maps.length(other_obj)
        if all(utils.definitely_true(st.solver, inv(st)) for st in states):
            print("Inferred len ", obj, "<=", other_obj)
            result.append(inv)
    return result

def get_items_invariants(obj, relevant_objs, states, ancestor_states, ancestor_variables):
    # TODO: Most of this logic was written back when map invariants were represented as Python lambdas,
    #       making comparisons hard; now that they are ASTs instead, we could compare them as part of heuristics,
    #       which would probably make some heuristics more robust and also more widely applicable...

    # helper function to get only the items that are definitely in the map associated with the given obj in the given state
    # TODO remove this, replace with implies(present, ...)
    def filter_present(state, obj):
        present_items = set()
        for i in state.maps[obj].known_items(_exclude_get=True):
            if utils.definitely_true(state.solver, claripy.And(i.present, *[i.key != pi.key for pi in present_items])):
                present_items.add(i)
        return present_items

    # helper function to find FK or FV
    def find_f(states, o1, o2, sel1, sel2, candidate_finders):
        # Returns False iff the candidate function cannot match each element in items1 with an element of items2
        def is_candidate_valid(items1, items2, candidate_func):
            for it1 in items1:
                # Here we could loop over all items in items2 at each iteration, to maximize our chance of
                # satisfying the candidate. Of course that would increase execution time... and doesn't seem necessary for now
                it2 = items2.pop()
                if utils.can_be_false(state.solver, sel2(it2.key, it2.value) == eval_map_ast(state, candidate_func(it1.key, it1.value))):
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
                # implementing backtracking in case a guess fails is hard :p and doesn't seem necessary for now
                raise Exception("backtracking not implemented yet")

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
                            # If is_candidate_valid returns false we could technically re-add it2 to items2 and try again with another item, but that doesn't seem necessary for now
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

    def candidate_finder_various(state, o1, o2, sel1, sel2, it1, it2):
        x1 = sel1(it1.key, it1.value)
        x2 = sel2(it2.key, it2.value)
        if x1.size() == x2.size():
            if utils.definitely_true(state.solver, x1 == x2):
                # Identity is a possible function
                return lambda k, v: sel1(k, v)

            fake = claripy.BVS("FAKE", x1.size(), explicit_name=True)
            if not x2.replace(x1, fake).structurally_match(x2):
                # Replacement is a possible function
                return lambda k, v, x1=x1, x2=x2: x2.replace(x1, sel1(k, v))

            # a few special cases on the concept of finding a function and its inverse
            # if x1 is "(0..x)" and x2 contains "x"
            if x1.op == "Concat" and \
              len(x1.args) == 2 and \
              x1.args[0].structurally_match(claripy.BVV(0, x1.args[0].size())):
                fake = claripy.BVS("FAKE", x1.args[1].size(), explicit_name=True)
                if not x2.replace(x1.args[1], fake).structurally_match(x2):
                    return lambda k, v, x1=x1, x2=x2: x2.replace(x1.args[1], claripy.Extract(x1.args[1].size() - 1, 0, sel1(k, v)))

            # if x1 is "(x..0) + n" where n is known from the ancestor and x2 contains "x"
            if x1.op == "__add__" and \
              len(x1.args) == 2 and \
              state.solver.variables(x1.args[1]).issubset(ancestor_variables) and \
              x1.args[0].op == "Concat" and \
              len(x1.args[0].args) == 2 and \
              x1.args[0].args[1].structurally_match(claripy.BVV(0, x1.args[0].args[1].size())):
                fake = claripy.BVS("FAKE", x1.args[0].args[0].size(), explicit_name=True)
                if not x2.replace(x1.args[0].args[0], fake).structurally_match(x2):
                    return lambda k, v, x1=x1, x2=x2: x2.replace(x1.args[0].args[0], claripy.Extract(x1.size() - 1, x1.args[0].args[1].size(), sel1(k, v) - x1.args[1]))
                if utils.definitely_true(state.solver, x2 == x1.args[0].args[0].zero_extend(x1.size() - x1.args[0].args[0].size())):
                    return lambda k, v, x1=x1: claripy.Extract(x1.size() - 1, x1.args[0].args[1].size(), sel1(k, v) - x1.args[1]).zero_extend(x1.args[0].args[1].size())
        return None

    def candidate_finder_constant(state, o1, o2, sel1, sel2, it1, it2):
        x2 = sel2(it2.key, it2.value)
        if sel2 is get_value:
            const = utils.get_if_constant(state.solver, x2)
            if const is not None:
                # A constant is a possible function
                return lambda k, v, const=const, sz=x2.size(): claripy.BVV(const, sz)
        return None

    # Helper function to find FP
    def find_fps(states, o, is_likely_array):
        fracs = states[0].heap.get_fractions(o)
        if fracs is not None:
            frac_fps = find_fps(states, fracs, True)
            return [lambda k, v: fp(k, MapGet(fracs, k, 8)) for fp in frac_fps]

        constants = {c for c in {utils.get_if_constant(state.solver, i.value) for state in states for i in filter_present(state, o)} if c is not None}
        return ([] if is_likely_array else [lambda k, v: claripy.true]) + [lambda k, v, c=c: v == claripy.BVV(c, v.size()) for c in constants]


    # Don't bother even trying if the obj is for fractions, nothing interesting we won't find with other objs
    if ancestor_states[0].heap.is_fractions(obj):
        return []

    # Optimization: Avoid inferring pointless invariants when maps are likely to be arrays.
    # If both maps are arrays of the same length, then the only interesting invariants are about the values in the 2nd map;
    # the keys obviously are related. Finding constant values is also likely pointless.
    # If only the first map is an array, using FP = True makes little sense, so don't try it.
    def is_likely_array(o):
        # Stupid, but it works, because these are the only arrays we create...
        return "allocated_addr" in str(o)
    obj_is_array = is_likely_array(obj)

    # Optimization: Ignore states in which the map did not change
    states = [st for st in states if st.maps[obj].version() != ancestor_states[0].maps[obj].version()]

    # Try to find FPs, early out if there are none
    fps = find_fps(states, obj, obj_is_array)
    if len(fps) == 0:
        return []

    # Convenience lambdas
    get_key = lambda k, v: k
    get_value = lambda k, v: v

    # For logging purposes only
    log_k = claripy.BVS("K", ancestor_states[0].maps.key_size(obj), explicit_name=True)
    log_v = claripy.BVS("V", ancestor_states[0].maps.value_size(obj), explicit_name=True)

    result = []
    for other_obj in relevant_objs:
        # Not the map itself
        if other_obj is obj: continue
        # Not maps that never changed (in the states we are concerned with, i.e., those in which our map changed)
        if all(st.maps[other_obj].version() == ancestor_states[0].maps[other_obj].version() for st in states): continue
        # Not the fractions corresponding to the map
        if ancestor_states[0].heap.get_fractions(other_obj) is obj: continue

        other_is_array = is_likely_array(other_obj)

        # Try to find a FK
        fk_finders = [candidate_finder_various]
        fk = find_f(states, obj, other_obj, get_key, get_key, fk_finders) \
          or find_f(states, obj, other_obj, get_value, get_key, fk_finders)
        # No point in continuing if we couldn't find a FK
        if fk is None: continue

        # Try to find a FV
        fv_finders = [candidate_finder_various]
        if not (obj_is_array and other_is_array):
            fv_finders.append(candidate_finder_constant)
        fv = find_f(states, obj, other_obj, get_key, get_value, fv_finders) \
          or find_f(states, obj, other_obj, get_value, get_value, fv_finders)

        for fp in fps:
            if fv is not None:
                inner_inv = lambda k, v, fp=fp, fk=fk, fv=fv, other_obj=other_obj: Implies(fp(k, v), MapHas(other_obj, fk(k, v), value=fv(k, v)))
                inv = lambda st, obj=obj, inner_inv=inner_inv: st.maps.forall(obj, inner_inv)
                if all(utils.definitely_true(st.solver, inv(st)) for st in states):
                    print(f"Inferred: when {obj} contains (K,V), if {fp(log_k, log_v)} then {other_obj} contains {fk(log_k, log_v)}")
                    print(f"          in addition, the value is {fv(log_k, log_v)}")
                    result.append(inv)
                    break
            # either no fv, or it didn't work
            inner_inv = lambda k, v, fp=fp, fk=fk, other_obj=other_obj: Implies(fp(k, v), MapHas(other_obj, fk(k, v)))
            inv = lambda st, obj=obj, inner_inv=inner_inv: st.maps.forall(obj, inner_inv)
            if all(utils.definitely_true(st.solver, inv(st)) for st in states):
                print(f"Inferred: when {obj} contains (K,V), if {fp(log_k, log_v)} then {other_obj} contains {fk(log_k, log_v)}")
                result.append(inv)
                break
    return result

# Returns (new_states, new_results, reached_fixpoint), where
# new_states is the new states to use instead of the ancestors,
# new_results is the results to pass as previous_results next time,
# reached_fixpoint is self-explanatory
# Assumes all ancestor_states have the same maps
def infer_invariants(ancestor_states, states, previous_results=None):
    if previous_results is None:
        previous_results = {}

    # Compute them once and for all
    ancestor_variables = get_variables(ancestor_states)

    # Ignore maps that have not changed at all
    relevant_objs = [o for (o, m) in ancestor_states[0].maps.get_all() if any(st.maps[o].version() != ancestor_states[0].maps[o].version() for st in states)]

    # Keep a copy of the states so we don't pollute them across attemps
    orig_states = [st.copy() for st in states]

    changed = False
    items_invariants = {}
    length_invariants = {}
    for obj in relevant_objs:
        states = [st.copy() for st in orig_states]

        # First, items
        (items_changed, invs) = flatten_items(obj, states, ancestor_states, ancestor_variables)
        items_invariants[obj.cache_key] = invs
        if items_changed:
            changed = True
            # Try and find some invariants since the maps' items changed, so we don't end up with overly simplistic invariants
            # that do not allow us to prove necessary facts. Most importantly, this will look for invariant across maps.
            items_invariants[obj.cache_key].extend(get_items_invariants(obj, relevant_objs, states, ancestor_states, ancestor_variables))

        # Second, length
        len_invs = previous_results.get(obj.cache_key, None)
        if len_invs is None:
            # This map's length has never changed before
            new_invs = get_length_invariants(obj, relevant_objs, states, ancestor_states)
            if new_invs is not None:
                length_invariants[obj.cache_key] = new_invs
                changed = True
        else:
            # There may be some invariants on this map's length (or there could be none)
            new_invs = []
            for inv in len_invs:
                for state in states:
                    if utils.can_be_false(state.solver, inv(state)):
                        changed = True
                        break
                else:
                    new_invs.append(inv)
            # Note that if len_invs was empty then new_invs is also empty and changed was not set to True,
            # which makes sense: there were no invariants so there are no changes, there are still no invariants (we gave up, in a sense)
            length_invariants[obj.cache_key] = new_invs

    # If we've reached a fixpoint, we're done
    if not changed:
        # Not the greatest place to put this or way to compute it, but anyway it's a very basic metric, some invariants are far more complex
        statistics.set_value("#invs", sum(len(m._invariants) for (_, m) in ancestor_states[0].maps.get_all()))
        return (None, None, True)

    # Otherwise, we create a new state per ancestor state with relaxed clones of each map...
    new_states = [st.copy() for st in ancestor_states]
    for state in new_states:
        for obj in relevant_objs:
            map = state.maps[obj]

            length_invs = length_invariants.get(obj.cache_key)
            if length_invs is None:
                # No need to change it
                new_length = map.length()
            else:
                new_length = claripy.BVS("havoced_length", map.length().size())

            state.maps[obj] = Map.new(
                state,
                map.meta.key_size,
                map.meta.value_size,
                map.meta.name,
                _invariants=[],
                _length=new_length,
                _exact_name=True
            )
        # ... and apply the invariants (must be done as a separate step so cross-map invariants reference updated maps)
        for obj in relevant_objs:
            for inv in items_invariants.get(obj.cache_key, []) + length_invariants.get(obj.cache_key, []):
                if isinstance(inv, MapInvariant):
                    state.solver.add(state.maps.forall(obj, inv))
                else:
                    state.solver.add(inv(state))

    # And we set the length invariant as the previous results for next time
    return (new_states, length_invariants, False)
