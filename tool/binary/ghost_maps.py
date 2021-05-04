from angr.state_plugins.plugin import SimStatePlugin
import claripy
import copy
import itertools
import os
import threading
import queue
from collections import namedtuple
from enum import Enum

import datetime

from binary import utils
from binary import statistics

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
        return ast.make_like(ast.op, [replacer(a) for a in ast.args[0:len(ast.args)-1]] + [state.maps[ast.args[0]].version()])
    return eval_map_ast_core(expr, {}, map_handler, map_handler)

def eval_map_ast(state, expr, replace_dict={}, condition=claripy.true):
    def has_handler(ast, replacer):
        replaced_key = replacer(ast.args[1])
        replaced_value = replacer(ast.args[2])
        if replaced_value is None:
            return state.maps[ast.args[0]].get(state, replaced_key, condition=condition, version=ast.args[2])[1]
        result = state.maps[ast.args[0]].get(state, replaced_key, conditioned_value=replaced_value, condition=condition, version=ast.args[3])
        return result[1] & (result[0] == replaced_value)
    def get_handler(ast, replacer):
        replaced_key = replacer(ast.args[1])
        return state.maps[ast.args[0]].get(state, replaced_key, condition=condition, version=ast.args[2])[0]
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
    def new(state, key_size, value_size, name, _invariants=None, _length=None, _name_counter=[0]): # use a list for the counter as a byref equivalent
        def to_int(n, name):
            if isinstance(n, int):
                return n
            if n.op == "BVV":
                return n.args[0]
            raise Exception(name + " cannot be symbolic")

        key_size = to_int(key_size, "key_size")
        value_size = to_int(value_size, "value_size")

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
        if self.is_empty():
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

        # Optimization: If the map length is concrete and there are definitely not too many items, don't even compute the known length
        if not self.length().symbolic and len(known_items) < self.length().args[0]:
            known_length_lte_total = claripy.true
        else:
            known_length_lte_total = self.known_length() <= self.length()

        state.solver.add(
            # Add K = K' => (V = V' and P = P') to the path constraint for each existing known item (K', V', P') in the map,
            *[Implies(key == i.key, (value == i.value) & (present == i.present)) for i in known_items + [self._unknown_item]],
            # Add UK => invariant(M)(K', V', P') to the path constraint [conditioned]
            *[Implies(unknown, inv(state, MapItem(key, value, present), condition=condition)) for inv in self.invariant_conjunctions()],
            # Add L <= length(M)
            known_length_lte_total
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

    def forall(self, state, pred, _exclude_get=False):
        if not isinstance(pred, MapInvariant):
            pred = MapInvariant.new(state, self.meta, (lambda i, old_pred=pred: Implies(i.present, old_pred(i.key, i.value))))

        LOG(state, "forall " + self.meta.name + "  " + str(pred))

        # Optimization: If the map is empty, the answer is always true
        if self.is_empty():
            return claripy.true

        known_items = self.known_items(_exclude_get=_exclude_get)
        known_items_result = claripy.And(*[pred(state, i) for i in known_items])

        unknown_is_not_known = claripy.And(*[self._unknown_item.key != i.key for i in known_items])
        unknown_items_result = Implies(self.known_length() < self.length(), Implies(unknown_is_not_known, pred(state, self._unknown_item)))
        # TODO try with just (since we don't really need the weird length=1 case)
        #unknown_items_result = Implies(unknown_is_not_known, pred(state, self._unknown_item))

        result = claripy.BoolS(self.meta.name + "_forall")
        state.solver.add(result == claripy.And(known_items_result, unknown_items_result))
        self.add_invariant_conjunction(state, pred.with_expr(lambda e, i: Implies(result, e)))
        LOGEND(state)
        return result

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

    def is_empty(self):
        l = self.length()
        return l.structurally_match(claripy.BVV(0, l.size()))

    # TODO this is only used in a kl < length context, can be specialized (with eg the opt of not even checking if the length is concrete and len(known_items) is smaller)
    def known_length(self):
        l = self.length()
        known_len = claripy.BVV(0, l.size())
        known_keys = []
        for item in self.known_items():
            key_is_new = claripy.And(*[item.key != k for k in known_keys])
            known_keys.append(item.key)
            known_len = known_len + claripy.If(key_is_new & item.present, claripy.BVV(1, l.size()), claripy.BVV(0, l.size()))
        return known_len

    def __copy__(self):
        return self.__deepcopy__({})

    def __deepcopy__(self, memo):
        result = Map(self.meta, self._length, copy.deepcopy(self._invariants, memo), copy.deepcopy(self._known_items, memo), copy.deepcopy(self._previous, memo), self._unknown_item, self._layer_item)
        memo[id(self)] = result
        return result

    def __repr__(self):
        return f"[Map {self.meta.name} v{self.version()}]"

    def _asdict(self): # pretend we are a namedtuple so functions that expect one will work (e.g. utils.structural_eq)
        return {'meta': self.meta, '_length': self._length, '_invariants': self._invariants, '_known_items': self._known_items, '_previous': self._previous, '_unknown_item': self._unknown_item, '_layer_item': self._layer_item}


class GhostMapsPlugin(SimStatePlugin):
    # === Public API ===

    def new(self, key_size, value_size, name, _length=None, _invariants=None): # TODO new_havoced instead of _length/_invariants?
        obj = claripy.BVS(name, self.state.sizes.ptr)
        self[obj] = Map.new(self.state, key_size, value_size, name, _length=_length, _invariants=_invariants)
        return obj

    def new_array(self, key_size, value_size, length, name):
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

    def forall(self, obj, pred, _exclude_get=False):
        return self[obj].forall(self.state, pred, _exclude_get=_exclude_get)

    # === Import and Export ===

    def get_all(self): # return .cache_key as keys!
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
        return GhostMapsPlugin(_maps=copy.deepcopy(self._maps, memo))

    def merge(self, others, merge_conditions, common_ancestor=None):
        # Very basic merging for now: only if they all match
        return all(utils.structural_eq(o._maps, self._maps) for o in others)


# state args have a leading _ to ensure that functions run concurrently don't accidentally touch them (TODO just move the functions out!)
def maps_merge_across(_states, objs, _ancestor_maps, _ancestor_variables, _cache={}):
    # TODO: Most of this logic was written back when map invariants were represented as Python lambdas,
    #       making comparisons hard; now that they are ASTs instead, we could compare them as part of heuristics,
    #       which would probably make some heuristics more robust and also more widely applicable...
    # TODO at least we should have a more systematic approach to optimizations that remove objs/states,
    #      and to what is and isn't parallelizable

    get_key = lambda k, v: k
    get_value = lambda k, v: v

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

    def clear_cached(o1, o2):
        _cache[o1][o2] = {k: (True, None) for k in ["k", "p", "v"]}

    # helper function to get only the items that are definitely in the map associated with the given obj in the given state
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
                # TODO: Here we could loop over all items in items2 at each iteration, to maximize our chance of
                # satisfying the candidate. Of course that would increase execution-time...
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
                # Lazyness: implementing backtracking in case a guess fails is hard :p
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
                            # TODO: If is_candidate_valid returns false we could technically re-add it2 to items2 and try again with another item
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
              state.solver.variables(x1.args[1]).issubset(_ancestor_variables) and \
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
        fracs = states[0].memory.get_fractions(o)
        if fracs is not None:
            frac_fps = find_fps(states, fracs, True)
            return [lambda k, v: fp(k, MapGet(fracs, k, 8)) for fp in frac_fps]

        constants = {c for c in {utils.get_if_constant(state.solver, i.value) for state in states for i in filter_present(state, o)} if c is not None}
        return ([] if is_likely_array else [lambda k, v: claripy.true]) + [lambda k, v, c=c: v == claripy.BVV(c, v.size()) for c in constants]

    # Initialize the cache for fast read and write acces during invariant inference
    init_cache(objs)

    remaining_work = queue.Queue() # all possible combinations of objects, plus once (o, None) per object
    results = queue.Queue() # pairs: (ID, maps, lambda states, maps: returns None for no changes or maps to overwrite them)
    to_cache = queue.Queue() # set_cached(...) will be called with all elements in there

    # Invariant inference algorithm: if some property P holds in all states to merge and the ancestor state, optimistically assume it is part of the invariant
    def thread_main(ancestor_maps, _orig_states):
        while True:
            try:
                (o1, o2) = remaining_work.get(block=False)
            except queue.Empty:
                return

            if o2 is None: # TODO this is a bit awkward
                # only for length
                if all(utils.definitely_true(st.solver, st.maps.length(o1) == ancestor_maps.length(o1)) for st in _orig_states):
                    #print("Inferred: Length of", o1, "has not changed")
                    results.put(("len-eq", [o1], lambda st, o1=o1: st.solver.add(st.maps.length(o1) == ancestor_maps.length(o1))))
                continue

            # Optimization: Ignore o1 as fractions, that's rather useless, and ignore o1/o2 as array and its fractions
            if _orig_states[0].memory.is_fractions(o1):
                continue
            if _orig_states[0].memory.get_fractions(o1) is o2:
                continue

            # Optimization: Ignore maps with a value size over a kilobyte, they're likely "buffer"-like, too big to seriously use as part of program logic
            if _orig_states[0].maps.value_size(o1) > 1024 * 8 or _orig_states[0].maps.value_size(o2) > 1024 * 8:
                continue

            # Optimization: Ignore the combination entirely if there are no states in which both maps changed
            if not any(st.maps[o1].version() != 0 and st.maps[o2].version() != 0 for st in _orig_states):
                #print("No states in which both changed for", o1, o2)
                continue

            #print("Considering", o1, o2, "at", datetime.datetime.now())

            # Length relationships.
            # For each pair of maps (M1, M2),
            #   if length(M1) <= length(M2) across all states,
            #   then assume this holds in the merged state
            # Only do that if the map didn't start with length 1, though, otherwise we catch "cell"-like maps that e.g. hold a state structure
            # TODO: It feels like in general we could do a better job to find length-related constraints...
            #       e.g. find equality across maps, and find == and <= constraints in path constraints, and drop this one
            if any(utils.can_be_false(st.solver, st.maps[o1].oldest_version().length() == 1) for st in _orig_states) and \
               any(utils.can_be_false(st.solver, st.maps[o2].oldest_version().length() == 1) for st in _orig_states) and \
               all(utils.definitely_true(st.solver, st.maps.length(o1) <= st.maps.length(o2)) for st in _orig_states):
                #print("Inferred: Length of", o1, "is always <= that of", o2)
                results.put(("len-le", [o1, o2], lambda st, o1=o1, o2=o2: st.solver.add(st.maps.length(o1) <= st.maps.length(o2))))

            # Optimization: Ignore the states in which neither map changed
            # (do this after len-le because otherwise we might only get the states in which length==1 for a map)
            orig_states = [st for st in _orig_states if st.maps[o1].version() != 0 or st.maps[o2].version() != 0]
            if len(orig_states) == 0:
                #print("Ignored all states for maps", o1, o2)
                continue

            # Map relationships.
            # For each pair of maps (M1, M2),
            #  if there exist functions FP, FK such that in all states, forall(M1, (K,V): FP(K,V) => get(M2, FK(K, V)) == (_, true)),
            #  then assume this is an invariant of M1 in the merged state.
            # Additionally,
            #  if there exists a function FV such that in all states, forall(M1, (K,V): FP(K,V) => get(M2, FK(K, V)) == (FV(K, V), true)),
            #  then assume this is an invariant of M1 in the merged state.
            # We use maps directly to refer to the map state as it was in the ancestor, not during execution;
            # otherwise, get(M1, k) after remove(M2, k) might add has(M2, k) to the constraints, which is obviously false

            states = [s.copy() for s in orig_states] # avoid polluting states across attempts

            # Optimization: Avoid inferring pointless invariants when maps are likely to be arrays.
            # If both maps are arrays of the same length, then the only interesting invariants are about the values in the 2nd map;
            # the keys obviously are related. Finding constant values is also likely pointless.
            # If only the first map is an array, using FP = True makes little sense, so don't try it.
            def is_likely_array(o):
                # Stupid, but it works, because these are the only arrays we create...
                return "allocated_addr" in str(o)
            o1_is_array = is_likely_array(o1)
            o2_is_array = is_likely_array(o2)

            # Try to find FPs
            (fps_is_cached, fps) = get_cached(o1, o2, "p")
            if not fps_is_cached:
                fps = find_fps(states, o1, o1_is_array)

            if fps == []:
                to_cache.put([o1, o2, "p", []])
                # No point in continuing if we couldn't find FPs
                continue

            # Try to find a FK
            (fk_is_cached, fk) = get_cached(o1, o2, "k")
            if not fk_is_cached:
                fk_finders = [candidate_finder_various]
                fk = find_f(states, o1, o2, get_key, get_key, fk_finders) \
                  or find_f(states, o1, o2, get_value, get_key, fk_finders)
            if not fk:
                to_cache.put([o1, o2, "k", None])
                # No point in continuing if we couldn't find a FK
                continue

            # Try to find a FV
            (fv_is_cached, fv) = get_cached(o1, o2, "v")
            if not fv_is_cached:
                fv_finders = [candidate_finder_various]
                if not (o1_is_array and o2_is_array):
                    fv_finders.append(candidate_finder_constant)
                fv = find_f(states, o1, o2, get_key, get_value, fv_finders) \
                  or find_f(states, o1, o2, get_value, get_value, fv_finders)

            log_k = claripy.BVS("K", states[0].maps.key_size(o1), explicit_name=True)
            log_v = claripy.BVS("V", states[0].maps.value_size(o1), explicit_name=True)
            #print("For", o1, o2, "found p,k,v:", [fp(log_k, log_v) for fp in fps], fk(log_k, log_v), fv(log_k, log_v) if fv is not None else "<none>", "at", datetime.datetime.now())
            for fp in fps:
                log_text = ""
                if fv and all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v, st=st, o2=o2, fp=fp, fk=fk, fv=fv: \
                                                                                             Implies(fp(k, v), MapHas(o2, fk(k, v), value=fv(k, v))), _exclude_get=True)) for st in states):
                        to_cache.put([o1, o2, "p", [fp]]) # only put the working one, don't have us try a pointless one next time
                        to_cache.put([o1, o2, "k", fk])
                        to_cache.put([o1, o2, "v", fv])
                        log_text +=   f"Inferred: when {o1} contains (K,V), if {fp(log_k, log_v)} then {o2} contains {fk(log_k, log_v)}"
                        log_text += f"\n          in addition, the value is {fv(log_k, log_v)}"
                        results.put(("x-value", [o1, o2],
                                     lambda state, o1=o1, o2=o2, fp=fp, fk=fk, fv=fv: state.solver.add(state.maps.forall(o1, lambda k, v: Implies(fp(k, v), MapHas(o2, fk(k, v), value=fv(k, v)))))))
                else:
                    to_cache.put([o1, o2, "v", None]) # do not cache fv since it didn't work

                    if all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v, st=st, o2=o2, fp=fp, fk=fk: Implies(fp(k, v), MapHas(o2, fk(k, v))), _exclude_get=True)) for st in states):
                        log_text += f"Inferred: when {o1} contains (K,V), if {fp(log_k, log_v)} then {o2} contains {fk(log_k, log_v)}"
                        results.put(("x-key", [o1, o2],
                                     lambda state, o1=o1, o2=o2, fp=fp, fk=fk: state.solver.add(state.maps.forall(o1, lambda k, v: Implies(fp(k, v), MapHas(o2, fk(k, v)))))))
                        to_cache.put([o1, o2, "p", [fp]]) # only put the working one, don't have us try a pointless one next time
                        to_cache.put([o1, o2, "k", fk])

                if log_text != "":
                    print(log_text) # print it at once to avoid interleavings from threads
                    break # this might make us miss some stuff in theory? but that's sound; and in practice it doesn't
            else:
                # executed if we didn't break, i.e., nothing found
                to_cache.put([o1, o2, "p", []])
                to_cache.put([o1, o2, "k", None])

    for o in objs:
        remaining_work.put((o, None))
    for (o1, o2) in itertools.permutations(objs, 2):
        remaining_work.put((o1, o2))

    # Multithreading disabled because:
    # - with threads, one needs to disable GC to avoid weird angr/Z3 issues (see angr issue #938), and it quickly OOMs unless there's tons of RAM
    # - with processes, we'd need to rearchitect this entire method to only pass pickle-able objects, i.e., never lambdas...
    thread_main(copy.deepcopy(_ancestor_maps), [s.copy() for s in _states])
    """threads = []
    import gc
    gc.disable()
    for n in range(os.cpu_count()): # os.sched_getaffinity(0) would be better (get the CPUs we might be restricted to) but is not available on Win and OSX
        t = threading.Thread(group=None, target=thread_main, name=None, args=[copy.deepcopy(_ancestor_maps), [s.copy() for s in _states]], kwargs=None, daemon=False)
        t.start()
        threads.append(t)
    for thread in threads:
        thread.join()
    gc.enable()"""

    # Convert results queue into a list
    results_list = []
    while not results.empty():
        results_list.append(results.get(block=False))

    # Fill cache
    while not to_cache.empty():
        set_cached(*(to_cache.get(block=False)))

    return results_list

def maps_merge_one(states_to_merge, obj, ancestor_maps, ancestor_variables, new_states):
    # Optimization: Drop states in which the map has not changed at all
    states_to_merge = [st for st in states_to_merge if st.maps[obj].version() != ancestor_maps[obj].version()]
    if len(states_to_merge) == 0:
        return False

    print("Merging map", obj)
    # helper function to find constraints that hold on an expression in a state
    def find_constraints(state, expr, replacement):
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

    # Oblivion algorithm: "forget" known items by integrating them into the unknown items invariant
    # For each conjunction in the unknown items invariant,
    # for each known item in any state,
    #  if the conjunction may not hold on that item assuming the item is present,
    #  find constraints that do hold and add them as a disjunction to the conjunction.
    # except this is done on the latest map versions... i.e. we take invs designed for v0 and apply them to vNow; not sure how to best phrase this
    changed = False
    invariant_conjs = []
    for conjunction in ancestor_maps[obj].invariant_conjunctions():
        for state in states_to_merge:
            for item in state.maps[obj].known_items(_exclude_get=True):
                conj = conjunction.with_latest_map_versions(state)(state, item)
                if utils.can_be_false(state.solver, Implies(item.present, conj)):
                    changed = True
                    conjunction = conjunction.with_expr(
                        lambda e, i, oldi=item, state=state: e | claripy.And(*find_constraints(state, oldi.key, i.key), *find_constraints(state, oldi.value, i.value))
                    )
                    print("Item", item, "in map", obj, "does not comply with invariant conjunction", conj, "; it is now", conjunction)
        invariant_conjs.append(conjunction)

    map_funcs = []
    new_map = ancestor_maps[obj].relax()
    for new_state in new_states:
        new_state.maps[obj] = new_map.__copy__()
        map_funcs.append(lambda st: [st.maps[obj].add_invariant_conjunction(st, inv) for inv in invariant_conjs])
        #for inv in invariant_conjs:
        #    new_state.maps[obj].add_invariant_conjunction(new_state, inv)

    return (changed, map_funcs)


# TODO TODO TODO rewrite this so we only do cross-inference for _new_ pairs (i.e., those that were outright ignored before)
# and the one-inference is used to tell if past invariants still hold (they're right there! we're already doing it!)

# Returns (new_states, new_results, reached_fixpoint), where
# new_states is the new states to use instead of the ancestors,
# new_results is the results to pass as previous_results next time,
# reached_fixpoint is self-explanatory
def infer_invariants(ancestor_states, states, previous_results=None):
    # note that we keep track of objs as their string representations to avoid comparing Claripy ASTs (which don't like ==)
    previous_results = copy.deepcopy(previous_results or [])

    # TODO it's ugly we're accessing _maps here...
    # also we should ensure all maps are equal modulo renaming, which is difficult
    ancestor_maps = ancestor_states[0].maps
    ancestor_objs = [o for (o, _) in ancestor_maps.get_all()]

    ancestor_variables = set(ancestor_states[0].solver.variables(claripy.And(*ancestor_states[0].solver.constraints)))
    for st in ancestor_states[1:]:
        ancestor_variables.intersection_update(st.solver.variables(claripy.And(*st.solver.constraints)))

    # Optimization: Ignore maps that have not changed at all
    ancestor_objs = [o for o in ancestor_objs if any(st.maps[o].version() != ancestor_maps[o].version() for st in states)]

    across_results = maps_merge_across(states, ancestor_objs, ancestor_maps, ancestor_variables)
    # To check if we have reached a superset of the previous results, remove all values we now have
    for (id, objs, _) in across_results:
        try:
            previous_results.remove((id, list(map(str, objs))))
        except ValueError:
            pass # was not in previous_results, that's OK

    new_states = [s.copy() for s in ancestor_states]

    # Merge individual values, keeping track of whether any of them changed
    any_individual_changed = False
    one_funcs = []
    for obj in ancestor_objs:
        (has_changed, funcs) = maps_merge_one(states, obj, ancestor_maps, ancestor_variables, new_states)
        any_individual_changed = any_individual_changed or has_changed
        one_funcs += funcs

    # Fixpoint if all merges resulted in the old result and the across_results are a superset
    reached_fixpoint = not any_individual_changed and len(previous_results) == 0
    if not reached_fixpoint:
        print("### No fixpoint yet, because:")
        if any_individual_changed:
            print("### - Individual items changed")
        if len(previous_results) != 0:
            print("### - Invariants were removed: " + str(previous_results))

    if reached_fixpoint:
        # No point in spending time setting up invariants on the new state if we won't use it
        new_states = None
    else:
        for new_state in new_states:
            for func in one_funcs:
                func(new_state)
            for (_, _, func) in across_results:
                func(new_state)
        statistics.set_value("#invs", sum(len(m._invariants) for (_, m) in new_states[0].maps.get_all()))

    new_results = [(id, list(map(str, objs))) for (id, objs, _) in across_results]
    return (new_states, new_results, reached_fixpoint)
