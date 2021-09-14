import angr
from angr.state_plugins.plugin import SimStatePlugin
import claripy
import copy

from kalm import utils


# Optimization: objects are compared structurally instead of with the solver, which might cause spurious failures
# (this does not work unless ghost maps are doing the "use existing items if possible in get" optimization)

# Key-value metadata per class
class MetadataPlugin(SimStatePlugin):
    def __init__(self, _items=None):
        SimStatePlugin.__init__(self)
        self._items = _items or {}

    @SimStatePlugin.memo
    def copy(self, memo):
        return MetadataPlugin(_items=copy.deepcopy(self._items, memo))

    def merge(self, others, merge_conditions, common_ancestor=None):
        # Very basic merging for now: only if they all match
        return all(utils.structural_eq(o._items, self._items) for o in others)

    def append(self, key, value):
        self._items.setdefault(type(value), {})[key.cache_key if key is not None else None] = value

    def get_all(self, cls):
        return {(k.ast if k is not None else None): v for (k, v) in self._items.get(cls, {}).items()}

    def get_one(self, cls):
        all = self._items.get(cls, {})
        if len(all) != 1:
            raise Exception("Not exactly one value")
        return next(iter(all.values()))

    def get_or_none(self, cls, key):
        all = self._items.get(cls, {})
        value = all.get(key.cache_key if key is not None else None, None)
        return value

    def get(self, cls, key, default_init=None):
        value = self.get_or_none(cls, key)
        if value is None:
            if default_init is None:
                raise Exception(f"No metadata of class {cls} for key: {key}")
            value = default_init()
            self.append(key, value)
        return value

    # find exactly one matching key; fails if >1, returns None if =0
    def find(self, cls, keys):
        all = self._items.get(cls, {})
        matching = []
        # First, avoid the solver if we can
        for key in keys:
            for (k, v) in all.items():
                if key.structurally_match(k.ast):
                    matching.append((k.ast, v))
        if len(matching) == 1:
            return matching[0]
        if len(matching) > 1:
            raise Exception("More than one match found for: " + str(keys))
        return (None, None)
