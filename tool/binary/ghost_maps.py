# Standard/External libraries
from angr.state_plugins.plugin import SimStatePlugin
import claripy
import copy
import itertools
import os
import threading
import queue
from collections import namedtuple
from enum import Enum

from timeit import default_timer as timer

# Us
from . import bitsizes
from . import utils
from . import hash_dict
from .exceptions import SymbexException


# NOTE: All optimizations should be periodically re-evaluated, since adding new features may make them pointless or even harmful
#       (e.g., making solver calls that are unnecessary due to some other change)


# Helper function to make expressions clearer
def Implies(a, b):
    return ~a | b

MapMeta = namedtuple("MapMeta", ["name", "key_size", "value_size"]) # sizes are ints (not BVs!), in bits
MapItem = namedtuple("MapItem", ["key", "value", "present"])

# value=None -> returns whether the map has the key; value!=None -> also checks whether the map has exactly that value for the key
def MapHas(map, key, value=None, version=None):
    return claripy.ast.Bool("MapHas", [map, key, value, version])

def MapGet(map, key, value_size, version=None):
    return claripy.ast.BV("MapGet", [map, key, version], length=value_size)

# Allow us to operate on these within expressions using replace_dict's leaf_operation parameter
claripy.operations.leaf_operations.add("MapHas")
claripy.operations.leaf_operations.add("MapGet")

def eval_map_ast_core(expr, replace_dict, has_handler, get_handler):
    # claripy.ast.Base.replace_dict needs a dict with .cache_key (to do something similar to our HashDict)
    replace_dict = {k.cache_key: v for (k,v) in replace_dict.items()}
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

def eval_map_ast(state, expr, replace_dict={}, conditions=[]):
    def has_handler(ast, replacer):
        replaced_key = replacer(ast.args[1])
        replaced_value = replacer(ast.args[2])
        if replaced_value is None:
            return state.maps.get(ast.args[0], replaced_key, conditions=conditions, version=ast.args[2])[1]
        result = state.maps.get(ast.args[0], replaced_key, value=replaced_value, conditions=conditions, version=ast.args[3])
        return result[1] & (result[0] == replaced_value)
    def get_handler(ast, replacer):
        replaced_key = replacer(ast.args[1])
        return state.maps.get(ast.args[0], replaced_key, conditions=conditions, version=ast.args[2])[0]
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

    def __call__(self, state, item, conditions=[]):
        return eval_map_ast(state, self.expr, replace_dict={self.key: item.key, self.value: item.value, self.present: item.present}, conditions=[item.present] + conditions)

    def __eq__(self, other):
        return self.expr.structurally_match(other.expr)

    def __repr__(self):
        return str(self.expr)

    def quick_implies(self, other): # if False, just means couldn't be determined quickly
        to_check = [(self.expr, other.expr)]
        while len(to_check) > 0:
            (l, r) = to_check.pop()
            if l.op != r.op: return False
            if len(l.args) != len(r.args): return False
            for (i, (la, ra)) in enumerate(zip(l.args, r.args)):
                if l.op == "MapHas" and i == 2 and ra is None:
                    # OK, MapHas with value implies MapHas without
                    continue
                if isinstance(la, claripy.ast.Base) and isinstance(ra, claripy.ast.Base):
                    to_check.append((la, ra))
                    continue
                if isinstance(la, claripy.ast.Base) or isinstance(ra, claripy.ast.Base):
                    return False
                if la != ra:
                    return False
        return True

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
            raise SymbexException(name + " cannot be symbolic")

        key_size = to_int(key_size, "key_size")
        value_size = to_int(value_size, "value_size")

        name = name + "_" + str(_name_counter[0])
        _name_counter[0] = _name_counter[0] + 1

        if _length is None:
            _length = 0
        if isinstance(_length, int):
            _length = claripy.BVV(_length, bitsizes.size_t)

        result = Map(MapMeta(name, key_size, value_size), _length, [], [])
        if _invariants is None:
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

    def get(self, state, key, value=None, conditions=[], version=None):
        if version is not None:
            to_call = self
            self_ver = self.version()
            while version < self_ver:
                to_call = to_call._previous
                version = version + 1
            return to_call.get(state, key, value=value, conditions=conditions)

        # Optimization: If the map is empty, the answer is always false
        if self.is_empty():
            return (claripy.BVS(self.meta.name + "_bad_value", self.meta.value_size), claripy.false)

        # If the map contains an item (K', V', P') such that K' = K, then return (V', P') [assuming the condition]
        known_items = self.known_items()
        matching_item = utils.get_exact_match(state.solver, key, known_items, assumptions=conditions, selector=lambda i: i.key)
        if matching_item is not None:
            return (matching_item.value, matching_item.present)

        # Let V be a fresh symbolic value [or the hint]
        if value is None:
            value = claripy.BVS(self.meta.name + "_value", self.meta.value_size)
        elif conditions:
            value = claripy.If(claripy.And(*conditions), value, claripy.BVS(self.meta.name + "_other_value", self.meta.value_size))

        # Let P be a fresh symbolic presence bit [or the existing condition]
        present = claripy.BoolS(self.meta.name + "_present")

        # Optimization: If the map length is concrete and there are definitely not too many items, don't even compute the known length
        if not self.length().symbolic and len(known_items) <= self.length().args[0]:
            known_length_lte_total = claripy.true
        else:
            known_length_lte_total = self.known_length() <= self.length()

        # Let UK be And(K != K') for each key K' in the map's known items
        unknown = claripy.And(*[key != i.key for i in known_items])

        new_constraints = [
            # Add K = K' => (V = V' and P = P') to the path constraint for each known item (K', V', P') in the map,
            *[Implies(key == i.key, (value == i.value) & (present == i.present)) for i in known_items],
            # Add UK => invariant(M)(K', V', P') to the path constraint [conditioned]
            Implies(unknown, claripy.And(*[inv(state, MapItem(key, value, present), conditions=conditions) for inv in self.invariant_conjunctions()])),
            # Add L <= length(M)
            known_length_lte_total
        ]

        # Optimization: If the item is definitely present or absent, replace P with a constant
        constant_present = utils.get_if_constant(state.solver, present, extra_constraints=new_constraints)
        if constant_present is not None:
            new_present = claripy.BoolV(constant_present)
            new_constraints = [c.replace(present, new_present) for c in new_constraints]
            present = new_present
        # Same with the value
        constant_value = utils.get_if_constant(state.solver, value, extra_constraints=new_constraints)
        if constant_value is not None:
            new_value = claripy.BVV(constant_value, value.size())
            new_constraints = [c.replace(value, new_value) for c in new_constraints]
            value = new_value

        utils.add_constraints_and_check_sat(state, *new_constraints)

        # MUTATE the map's known items by adding (K, V, P) [conditioned]
        self.add_item(MapItem(key, value, present))

        # Return (V, P)
        return (value, present)

    def set(self, state, key, value, UNSAFE_can_flatten=False): # see GhostMapsPlugin.set for an explanation of UNSAFE_can_flatten
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
            map=lambda i: MapItem(i.key, claripy.If(i.key == key, value, i.value), claripy.If(i.key == key, claripy.true, i.present)),
            UNSAFE_can_flatten=UNSAFE_can_flatten
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

    def forall(self, state, pred):
        # NOTE: pred is a MapInvariant here, we already did present=>pred in GhostMapsPlugin.forall
        # TODO: add type annotations everywhere...

        # Optimization: If the map is empty, the answer is always true
        if self.is_empty():
            return claripy.true

        # Optimization: No need to go further if we already have an invariant known to imply the predicate
        for inv in self.invariant_conjunctions():
            if inv.quick_implies(pred):
                return result

        # Let K' be a fresh symbolic key, V' a fresh symbolic value, and P' a fresh symbolic presence bit
        test_key = claripy.BVS(self.meta.name + "_test_key", self.meta.key_size)
        test_value = claripy.BVS(self.meta.name + "_test_value", self.meta.value_size)
        test_present = claripy.BoolS(self.meta.name + "_test_present")
        test_item = MapItem(test_key, test_value, test_present)

        # Let L be the number of known items whose presence bit is set
        # Let F = ((P1 => pred(K1, V1)) and (P2 => pred(K2, V2)) and (...) and ((L < length(M)) => (invariant(M)(K', V', P') => (P' => pred(K', V')))))

        # Optimization: Exclude items resulting from a call to 'get', they are implicitly tested through the unknown items invariant
        known_items_result = claripy.And(*[pred(state, i) for i in self.known_items(exclude_get=True)])

        # Optimization: We can start by testing the invariant conjunctions one by one, if we find one that definitely implies then the overall invariant definitely implies pred
        #               We expect this to be the common case during invariant inference
        for inv in self.invariant_conjunctions():
            if utils.definitely_true(state.solver, Implies(inv(state, test_item), pred(state, test_item))):
                return known_items_result

        unknown_items_result = Implies(claripy.And(*[inv(state, test_item) for inv in self.invariant_conjunctions()]), pred(state, test_item))

        result = known_items_result & Implies(self.known_length() < self.length(), unknown_items_result)

        # Optimization: No need to change the invariant if the predicate definitely holds or does not hold,
        # since in the former case it is already implied and in the latter case it would add nothing
        const_result = utils.get_if_constant(state.solver, result)
        if const_result is not None:
            return claripy.true if const_result else claripy.false

        # MUTATE the map's invariant by adding F => (P => pred(K, V))
        self.add_invariant_conjunction(state, pred.with_expr(lambda e, i: Implies(result, e)))

        # Return F
        return result

    # Havocs the map contents, mutating the map, with the given optional max_length (otherwise uses the current one)
    # Do not use unless you know what you're doing; this is intended for init only, to mimic an external program configuring a map
    def havoc(self, state, max_length, is_array):
        if max_length is not None:
            self._length = claripy.BVS("havoced_length", max_length.size())
            utils.add_constraints_and_check_sat(state, self._length.ULE(max_length))
        if is_array:
            self._invariants = [MapInvariant.new(state, self.meta, lambda i, length=self._length: (i.key < length) == i.present)]
        else:
            self._invariants = [MapInvariant.new(state, self.meta, lambda i: claripy.true)]
        self._known_items = []
        self.ever_havoced = True

    # === Private API, also used by invariant inference ===

    def __init__(self, meta, length, invariants, known_items, _previous=None, _filter=None, _map=None, ever_havoced=False):
        # "length" is symbolic, and may be larger than len(items) if there are items that are not exactly known
        # "invariants" is a list of conjunctions that represents unknown items: each is a lambda that takes (state, item) and returns a Boolean expression
        # "items" contains exactly known items, which do not have to obey the invariants
        self.meta = meta
        self._length = length
        self._invariants = invariants
        self._known_items = known_items
        self._previous = _previous
        # Do not use defaults for _filter and _map so that flattened maps can be serialized easily (i.e., without referring to lambdas)
        self._filter = _filter
        self._map = _map
        self.ever_havoced = ever_havoced

    def version(self):
        if self._previous is None: return 0
        else: return 1 + self._previous.version()

    def invariant_conjunctions(self):
        if self._previous is None:
            return self._invariants
        return self._invariants + self._previous.invariant_conjunctions()

    def add_invariant_conjunction(self, state, inv):
        if isinstance(inv, MapInvariant):
            self._invariants.append(inv)
        else:
            self._invariants.append(MapInvariant.new(state, self.meta, inv))

    def with_invariant_conjunctions(self, new_invariant_conjunctions):
        result = self.__copy__()
        result._invariants = new_invariant_conjunctions
        return result

    def known_items(self, exclude_get=False):
        if self._previous is None and exclude_get:
            # we are in version 0, which only has items added by a call to 'get'
            return []
        return self._known_items + list(map(self._map or (lambda i: i), filter(self._filter or (lambda i: True), () if self._previous is None else self._previous.known_items(exclude_get=exclude_get))))

    def add_item(self, item):
        if self._previous is None:
            self._known_items.append(item)
        else:
            self._previous.add_item(item)

    def with_items_layer(self, items, length_change, filter, map, UNSAFE_can_flatten=False):
        if UNSAFE_can_flatten:
            return Map(
                self.meta,
                self._length + length_change,
                self._invariants,
                [map(i) for i in self._known_items if filter(i)] + items,
                _previous=self._previous,
                _filter=lambda i, old=filter: old(i) and filter(i),
                _map=lambda i, old=map: map(old(i))
            )
        return Map(
            self.meta,
            self._length + length_change,
            [], # no extra invariants, just use the ones in _previous
            items,
            _previous=self,
            _filter=filter,
            _map=map
        )

    def flatten(self, keep_known_items=False):
        return Map(
            self.meta,
            self._length,
            self.invariant_conjunctions(),
            self.known_items() if keep_known_items else [] # useful for exporting data without also exporting _map/_filter which are lambdas
        )

    def set_length(self, new_length):
        self._length = new_length

    def is_empty(self):
        l = self.length()
        return l.structurally_match(claripy.BVV(0, l.size()))

    def known_length(self):
        START = timer()
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
        result = Map(self.meta, self._length, copy.deepcopy(self._invariants, memo), copy.deepcopy(self._known_items, memo), copy.deepcopy(self._previous, memo), self._filter, self._map, self.ever_havoced)
        memo[id(self)] = result
        return result

    def __repr__(self):
        return f"[Map {self.meta.name} v{self.version()}]"

    def _asdict(self): # pretend we are a namedtuple so functions that expect one will work (e.g. utils.structural_eq)
        return {'meta': self.meta, '_length': self._length, '_invariants': self._invariants, '_known_items': self._known_items, '_previous': self._previous, '_filter': self._filter, '_map': self._map}


# Recording stuff
RecordNew = namedtuple('RecordNew', ['key_size', 'value_size', 'result'])
RecordNewArray = namedtuple('RecordNewArray', ['key_size', 'value_size', 'length', 'result'])
RecordLength = namedtuple('RecordLength', ['obj', 'result'])
RecordGet = namedtuple('RecordGet', ['obj', 'key', 'result'])
RecordSet = namedtuple('RecordSet', ['obj', 'key', 'value'])
RecordRemove = namedtuple('RecordRemove', ['obj', 'key'])
RecordForall = namedtuple('RecordForall', ['obj', 'pred', 'result'])

class GhostMapsPlugin(SimStatePlugin):
    # === Public API ===

    def new(self, key_size, value_size, name):
        obj = claripy.BVS(name, bitsizes.ptr)
        self.state.metadata.set(obj, Map.new(self.state, key_size, value_size, name))
        self.state.path.ghost_record(lambda: RecordNew(key_size, value_size, obj))
        return obj

    def new_array(self, key_size, value_size, length, name):
        obj = claripy.BVS(name, bitsizes.ptr)
        self.state.metadata.set(obj, Map.new_array(self.state, key_size, value_size, length, name))
        self.state.path.ghost_record(lambda: RecordNewArray(key_size, value_size, length, obj))
        return obj

    def length(self, obj):
        result = self[obj].length()
        self.state.path.ghost_record(lambda: RecordLength(obj, result))
        return result

    def key_size(self, obj):
        return self[obj].meta.key_size

    def value_size(self, obj):
        return self[obj].meta.value_size

    def get(self, obj, key, value=None, conditions=[], version=None):
        map = self[obj]
        LOG(self.state, "GET " + str(obj) + f" version: {version} " + (" key: " + str(key)) + ((" value: " + str(value)) if value is not None else "") + \
            ((" cond: " + str(conditions)) if conditions else "")  + \
                        " (" + str(len(list(map.known_items()))) + " items, " + str(len(self.state.solver.constraints)) + " constraints)")
        result = map.get(self.state, key, value=value, conditions=conditions, version=version)
        LOGEND(self.state)
        self.state.path.ghost_record(lambda: RecordGet(obj, key, result))
        return result

    def set(self, obj, key, value, UNSAFE_can_flatten=False):
        # UNSAFE_can_flatten, as its name implies, is only safe if the map has not been used for anything else (e.g. an invariant of another map)
        # This is an optimization aimed at memory. Ideally we'd remove it because it's weird and requires being careful,
        # but as long as we have big concrete slabs of memory for RX/TX descriptors we need it.
        self.state.metadata.set(obj, self[obj].set(self.state, key, value, UNSAFE_can_flatten=UNSAFE_can_flatten), override=True)
        self.state.path.ghost_record(lambda: RecordSet(obj, key, value))

    def remove(self, obj, key):
        self.state.metadata.set(obj, self[obj].remove(self.state, key), override=True)
        self.state.path.ghost_record(lambda: RecordRemove(obj, key))

    def forall(self, obj, pred):
        map = self[obj]
        pred = MapInvariant.new(self.state, map.meta, (lambda i, old_pred=pred: Implies(i.present, old_pred(i.key, i.value))))
        LOG(self.state, "forall " + str(obj) + " ( " + str(len(self.state.solver.constraints)) + " constraints)")
        result = map.forall(self.state, pred)
        LOGEND(self.state)
        self.state.path.ghost_record(lambda: RecordForall(obj, pred, result))
        return result

    # === Havocing, to mimic BPF userspace ===

    def havoc(self, obj, max_length, is_array):
        self[obj].havoc(self.state, max_length, is_array)

    # === Import/Export ===

    def get_all(self):
        return list(self.state.metadata.get_all(Map))

    def set_all(self, items):
        self.state.metadata.remove_all(Map)
        for (obj, m) in items:
            self.state.metadata.set(obj, m)

    # === Private API, including for invariant inference ===

    def __init__(self):
        SimStatePlugin.__init__(self)

    @SimStatePlugin.memo
    def copy(self, memo):
        return GhostMapsPlugin()

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

# state args have a leading _ to ensure that functions run concurrently don't accidentally touch them
def maps_merge_across(_states_to_merge, objs, _ancestor_state, _cache={}):
    print(f"Cross-merge of maps starting. State count: {len(_states_to_merge)}")

    # NOTE: Most of this logic was written back when map invariants were represented as Python lambdas,
    #       making comparisons hard; now that they are ASTs instead, we could compare them as part of heuristics,
    #       which would probably make some heuristics more robust and also more widely applicable...

    _states = _states_to_merge + [_ancestor_state]

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

    def clear_cached(o1, o2):
        _cache[o1][o2] = {k: (True, None) for k in ["k", "p", "v"]}

    # helper function to get only the items that are definitely in the map associated with the given obj in the given state
    def filter_present(state, obj, exclude_get=False):
        present_items = set()
        for i in state.maps[obj].known_items(exclude_get=exclude_get):
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
                if utils.can_be_false(state.solver, sel2(items2.pop()) == eval_map_ast(state, candidate_func(it1))):
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

    def candidate_finder_various(state, o1, o2, sel1, sel2, it1, it2):
        x1 = sel1(it1)
        x2 = sel2(it2)
        if x1.size() == x2.size():
            if utils.definitely_true(state.solver, x1 == x2):
                # Identity is a possible function
                return lambda it: sel1(it)

            fake = claripy.BVS("fake", x1.size())
            if not x2.replace(x1, fake).structurally_match(x2):
                # Replacement is a possible function
                return lambda it, x1=x1, x2=x2: x2.replace(x1, sel1(it))

            # a few special cases on the concept of finding a function and its inverse
            # if x1 is "(0..x)" and x2 contains "x"
            if x1.op == "Concat" and \
            len(x1.args) == 2 and \
            x1.args[0].structurally_match(claripy.BVV(0, x1.args[0].size())):
                fake = claripy.BVS("fake", x1.args[1].size())
                if not x2.replace(x1.args[1], fake).structurally_match(x2):
                    return lambda it, x1=x1, x2=x2: x2.replace(x1.args[1], claripy.Extract(x1.args[1].size() - 1, 0, sel1(it)))

            # if x1 is "(x..0) + n" where n is known from the ancestor and x2 contains "x"
            if x1.op == "__add__" and \
            len(x1.args) == 2 and \
            state.solver.variables(x1.args[1]).issubset(ancestor_variables) and \
            x1.args[0].op == "Concat" and \
            len(x1.args[0].args) == 2 and \
            x1.args[0].args[1].structurally_match(claripy.BVV(0, x1.args[0].args[1].size())):
                fake = claripy.BVS("fake", x1.args[0].args[0].size())
                if not x2.replace(x1.args[0].args[0], fake).structurally_match(x2):
                    return lambda it, x1=x1, x2=x2: x2.replace(x1.args[0].args[0], claripy.Extract(x1.size() - 1, x1.args[0].args[1].size(), sel1(it) - x1.args[1]))
                if utils.definitely_true(state.solver, x2 == x1.args[0].args[0].zero_extend(x1.size() - x1.args[0].args[0].size())):
                    return lambda it, x1=x1: claripy.Extract(x1.size() - 1, x1.args[0].args[1].size(), sel1(it) - x1.args[1]).zero_extend(x1.args[0].args[1].size())
        return None

    def candidate_finder_othermap(state, o1, o2, sel1, sel2, it1, it2):
        # The ugliest one: if o1 is a "fractions" obj, check if the corresponding value in the corresponding obj is equal to x2
        if sel1 is get_key:
            # note that orig_size is in bytes, but x2.size() is in bits!
            orig_o1, orig_size = state.memory.get_obj_and_size_from_fracs_obj(o1)
            x2 = sel2(it2)
            if orig_o1 is not None and orig_o1 is not o2 and utils.definitely_true(state.solver, orig_size * 8 == x2.size()):
                (orig_x1v, orig_x1p) = state.maps.get(orig_o1, it1.key)
                if utils.definitely_true(state.solver, orig_x1p & (orig_x1v == x2)):
                    return lambda it, orig_o1=orig_o1, x2size=x2.size(): MapGet(orig_o1, it.key, x2size)
        return None

    def candidate_finder_constant(state, o1, o2, sel1, sel2, it1, it2):
        x2 = sel2(it2)
        if sel2 is get_value:
            const = utils.get_if_constant(state.solver, x2)
            if const is not None:
                # A constant is a possible function
                return lambda it, const=const, sz=x2.size(): claripy.BVV(const, sz)
        return None

    # Helper function to find FP
    def find_fps(states, o, sel, is_likely_array):
        constants = {c for c in {utils.get_if_constant(state.solver, sel(i)) for state in states for i in filter_present(state, o, exclude_get=True)} if c is not None}
        return ([] if is_likely_array else [lambda i: claripy.true]) + [lambda i, c=c: sel(i) == claripy.BVV(c, sel(i).size()) for c in constants]

    # Optimization: If _all_ non-frac maps were havoced in the initial state, there are no invariants to find
    if all(_ancestor_state.maps[o].ever_havoced or _ancestor_state.memory.get_obj_and_size_from_fracs_obj(o) != (None, None) for o in objs):
        return []

    # Initialize the cache for fast read/write acces during invariant inference
    init_cache(objs)

    results = queue.Queue() # pairs: (ID, maps, lambda states, maps: returns None for no changes or maps to overwrite them)
    to_cache = queue.Queue() # set_cached(...) will be called with all elements in there

    # Invariant inference algorithm: if some property P holds in all states to merge and the ancestor state, optimistically assume it is part of the invariant

    # Optimization: Ignore maps that have not changed at all
    objs = [o for o in objs if any(st.maps[o].version() != _ancestor_state.maps[o].version() for st in _states_to_merge)]

    for o in objs:
        # Step 1: Length variation.
        # If the length may have changed in any state from the one in the ancestor state,
        # replace the length with a fresh symbol
        ancestor_length = _ancestor_state.maps.length(o)
        for state in _states_to_merge:
            if utils.can_be_false(state.solver, state.maps.length(o) == ancestor_length):
                print("Length of map", o, " was changed; making it symbolic")
                results.put((ResultType.LENGTH_VAR, [o], lambda st, ms: ms[0].set_length(claripy.BVS("map_length", ms[0].length().size()))))
                break

    def thread_main(ancestor_state, _orig_states):
        while True:
            try:
                (o1, o2) = remaining_work.get(block=False)
            except queue.Empty:
                return

            # Optimization: Ignore the combination if neither map changed
            orig_states = [st for st in _orig_states if st.maps[o1].version() != 0 or st.maps[o2].version() != 0]
            if len(orig_states) == 0:
                continue

            # Step 2: Length relationships.
            # For each pair of maps (M1, M2),
            #   if length(M1) <= length(M2) across all states,
            #   then assume this holds in the merged state
            if all(utils.definitely_true(st.solver, st.maps.length(o1) <= st.maps.length(o2)) for st in orig_states):
                #print("Inferred: Length of", o1, "is always <= that of", o2)
                results.put((ResultType.LENGTH_LTE, [o1, o2], lambda st, ms: st.add_constraints(ms[0].length() <= ms[1].length())))

            # Step 3: Map relationships.
            # For each pair of maps (M1, M2),
            #  if there exist functions FP, FK such that in all states, forall(M1, (K,V): FP(K,V) => get(M2, FK(K, V)) == (_, true)),
            #  then assume this is an invariant of M1 in the merged state.
            # Additionally,
            #  if there exists a function FV such that in all states, forall(M1, (K,V): FP(K,V) => get(M2, FK(K, V)) == (FV(K, V), true)),
            #  then assume this is an invariant of M1 in the merged state.
            # We use maps directly to refer to the map state as it was in the ancestor, not during execution;
            # otherwise, get(M1, k) after remove(M2, k) might add has(M2, k) to the constraints, which is obviously false

            states = [s.copy() for s in orig_states] # avoid polluting states across attempts

            # Try to find a FK
            (fk_is_cached, fk) = get_cached(o1, o2, "k")
            if not fk_is_cached:
                fk_finders = [candidate_finder_various, candidate_finder_othermap]
                fk = find_f(states, o1, o2, get_key, get_key, fk_finders) \
                  or find_f(states, o1, o2, get_value, get_key, fk_finders)
            if not fk:
                to_cache.put([o1, o2, "k", None])
                # No point in continuing if we couldn't find a FK
                continue

            # Optimization: Avoid inferring pointless invariants when maps are likely to be arrays.
            # If both maps are arrays of the same length, then the only interesting invariants are about the values in the 2nd map;
            # the keys obviously are related. Finding constant values is also likely pointless.
            # If only the first map is an array, using FP = True makes little sense, so don't try it.
            o1_is_array = False
            o2_is_array = False
            if not fk_is_cached:
                def is_likely_array(o):
                    return ancestor_state.maps.key_size(o) == ancestor_state.maps.length(o).size() and \
                           all(utils.definitely_true(st.solver, (st.maps.length(o) == ancestor_state.maps.length(o)) & st.maps.forall(o, lambda k, v: k < st.maps.length(o))) for st in states)
                o1_is_array = is_likely_array(o1)
                o2_is_array = is_likely_array(o2)

            # Try to find a few FPs
            (fps_is_cached, fps) = get_cached(o1, o2, "p")
            if not fps_is_cached:
                fps = find_fps(states, o1, get_value, o1_is_array)

            for fp in fps:
                if all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v, st=st, o2=o2, fp=fp, fk=fk: Implies(fp(MapItem(k, v, None)), MapHas(o2, fk(MapItem(k, v, None)))))) for st in states):
                    log_item = MapItem(claripy.BVS("K", ancestor_state.maps.key_size(o1), explicit_name=True), claripy.BVS("V", ancestor_state.maps.value_size(o1), explicit_name=True), None)
                    log_text = f"Inferred: when {o1} contains (K,V), if {fp(log_item)} then {o2} contains {fk(log_item)}"

                    # Try to find a FV
                    (fv_is_cached, fv) = get_cached(o1, o2, "v")
                    if not fv_is_cached:
                        fv_finders = [candidate_finder_various, candidate_finder_othermap]
                        if not (o1_is_array and o2_is_array):
                            fv_finders.append(candidate_finder_constant)
                        fv = find_f(states, o1, o2, get_key, get_value, fv_finders) \
                          or find_f(states, o1, o2, get_value, get_value, fv_finders)

                    if fv and all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v, st=st, o2=o2, fp=fp, fk=fk, fv=fv: \
                                                                                             Implies(fp(MapItem(k, v, None)), MapHas(o2, fk(MapItem(k, v, None)), value=fv(MapItem(k, v, None)))))) for st in states):
                        to_cache.put([o1, o2, "v", fv])
                        log_text += f"\n          in addition, the value is {fv(log_item)}"
                        results.put((ResultType.CROSS_VAL, [o1, o2],
                                     lambda state, maps, o2=o2, fp=fp, fk=fk, fv=fv: maps[0].add_invariant_conjunction(state, lambda i: Implies(i.present, Implies(fp(i), MapHas(o2, fk(i), value=fv(i)))))))
                    else:
                        to_cache.put([o1, o2, "v", None]) # do not cache fv since it didn't work
                        if o2_is_array:
                            # Cache it as a failure as well
                            to_cache.put([o1, o2, "k", None])
                            to_cache.put([o1, o2, "p", []])
                            break
                        results.put((ResultType.CROSS_KEY, [o1, o2],
                                     lambda state, maps, o2=o2, fp=fp, fk=fk: maps[0].add_invariant_conjunction(state, lambda i: Implies(i.present, Implies(fp(i), MapHas(o2, fk(i)))))))

                    to_cache.put([o1, o2, "k", fk])
                    to_cache.put([o1, o2, "p", [fp]]) # only put the working one, don't have us try a pointless one next time
                    print(log_text) # print it at once to avoid interleavings from threads
                    break # this might make us miss some stuff in theory? but that's sound; and in practice it doesn't
            else:
                to_cache.put([o1, o2, "k", None])
                to_cache.put([o1, o2, "p", []])

    remaining_work = queue.Queue()
    for (o1, o2) in itertools.permutations(objs, 2):
        remaining_work.put((o1, o2))

    # Multithreading disabled because it causes weird errors (maybe we're configuring angr wrong; we end up with a claripy mixin shared between threads)
    # and even segfaults (which look like z3 is accessed concurrently when it shouldn't be)
    # See https://github.com/angr/angr/issues/938
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

    def remove_results(lst, match):
        to_remove = [r for r in lst if match(r)]
        # cannot just use "r not in" due to claripy's == behavior
        to_remove_ids = {id(r) for r in to_remove}
        remaining = [r for r in lst if id(r) not in to_remove_ids]
        return remaining, to_remove

    # Optimization: Remove redundant inferences.
    # That is, for pairs (M1, M2) of maps whose keys are the same in all states and which lead to the same number of inferences,
    # remove all map relationships of the form (M2, M3) if (M1, M3) exists, as well as those of the form (M3, M2) if (M3, M1) exists.
    # This is a conservative algorithm; a better version eliminating more things would need to keep track of whether relationships are lossy,
    # to avoid eliminating a lossless relationship in favor of a lossy one, and create a proper graph instead of relying on pairs.
    for (o1, o2) in itertools.combinations(objs, 2):
        if _ancestor_state.maps.key_size(o1) == _ancestor_state.maps.key_size(o2) and \
           sum(1 for r in cross_results if r[1][0] is o1) == sum(1 for r in cross_results if r[1][0] is o2):
            states = [s.copy() for s in _orig_states]
            if all(utils.definitely_true(st.solver, st.maps.forall(o1, lambda k, v: MapHas(o2, k))) for st in states):
                cross_results, removed = remove_results(
                    cross_results,
                    lambda r: (r[1][0] is o2 and any(r2[1][0] is o1 and r2[1][1] is r[1][1] for r2 in cross_results)) \
                           or (r[1][1] is o2 and any(r2[1][1] is o1 and r2[1][0] is r[1][0] for r2 in cross_results))
                )
                for r in removed:
                    print(f"Discarding redundant inference {r[0]} between {r[1]}")

    return cross_results + length_results

def maps_merge_one(states_to_merge, obj, ancestor_state):
    # Do not even consider maps that have not changed at all, e.g. those that are de facto readonly after initialization
    # This is not an optimization, if we don't check this we'll end up havocing the contents of e.g. a "state" struct
    # in theory this could be fine if we collected constraints about it like "the first 64 bits are the pointer to another struct"
    # but we don't, so.
    if all(utils.structural_eq(ancestor_state.maps[obj], st.maps[obj]) for st in states_to_merge):
        return (ancestor_state.maps[obj], False)

    # Optimization: Drop states in which the map has not changed at all
    states_to_merge = [st for st in states_to_merge if not utils.structural_eq(ancestor_state.maps[obj], st.maps[obj])]

    print("Merging map", obj)
    # helper function to find constraints that hold on an expression in a state
    ancestor_variables = ancestor_state.solver.variables(claripy.And(*ancestor_state.solver.constraints))
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
    invariant_conjs = []
    changed = False
    for conjunction in ancestor_state.maps[obj].invariant_conjunctions():
        for state in states_to_merge:
            for item in state.maps[obj].known_items(exclude_get=True):
                conj = conjunction.with_latest_map_versions(state)(state, item)
                if utils.can_be_false(state.solver, Implies(item.present, conj)):
                    changed = True
                    conjunction = conjunction.with_expr(
                        lambda e, i, oldi=item, state=state: e | claripy.And(*find_constraints(state, oldi.key, i.key), *find_constraints(state, oldi.value, i.value))
                    )
                    print("Item", item, "in map", obj, "does not comply with invariant conjunction", conj)
        invariant_conjs.append(conjunction)

    return (ancestor_state.maps[obj].flatten().with_invariant_conjunctions(invariant_conjs), changed)


# Returns (new_state, new_results, reached_fixpoint), where
# new_state is the new state to use instead of the ancestor,
# new_results is the results to pass as previous_results next time,
# reached_fixpoint is self-explanatory
def infer_invariants(ancestor_state, states, previous_results=None):
    # note that we keep track of objs as their string representations to avoid comparing Claripy ASTs (which don't like ==)
    previous_results = copy.deepcopy(previous_results or [])
    ancestor_objs = [o for (o, _) in ancestor_state.maps.get_all()]

    across_results = maps_merge_across(states, ancestor_objs, ancestor_state)
    # To check if we have reached a superset of the previous results, remove all values we now have
    for (id, objs, _) in across_results:
        try:
            previous_results.remove((id, list(map(str, objs))))
        except ValueError:
            pass # was not in previous_results, that's OK

    # Merge individual values, keeping track of whether any of them changed
    any_individual_changed = False
    merged_maps = []
    for obj in ancestor_objs:
        (merged_value, has_changed) = maps_merge_one(states, obj, ancestor_state)
        any_individual_changed = any_individual_changed or has_changed
        merged_maps.append((obj, merged_value))

    # Fixpoint if all merges resulted in the old result and the across_results are a superset
    reached_fixpoint = not any_individual_changed and len(previous_results) == 0
    if not reached_fixpoint:
        print("### No fixpoint yet, because:")
        if any_individual_changed:
            print("### - Individual items changed")
        if len(previous_results) != 0:
            print("### - Invariants were removed: " + str(previous_results))

    new_results = [(id, list(map(str, objs))) for (id, objs, _) in across_results]
    new_state = ancestor_state.copy()
    new_state.maps.set_all(merged_maps)

    for (_, objs, func) in across_results:
        vals = [new_state.maps[obj] for obj in objs]
        func(new_state, vals)

    return (new_state, new_results, reached_fixpoint)