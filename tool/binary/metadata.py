import angr
import claripy
from angr.state_plugins.plugin import SimStatePlugin
import copy

from . import utils


# Optimization: objects are compared structurally instead of with the solver, which might cause spurious failures
# (this does not work unless ghost maps are doing the "use existing items if possible in get" optimization)

# Append-only key-value metadata per class
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
        return {k.ast: v for (k, v) in self._items.get(cls, {}).items()}

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
