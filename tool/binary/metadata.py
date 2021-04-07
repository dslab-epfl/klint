import angr
import claripy
from angr.state_plugins.plugin import SimStatePlugin
import copy

from . import utils

# TODO can we specialize this class? remove it? use ghost maps directly instead somehow (eg an enum for IDs)?

# Optimization: objects are compared structurally instead of with the solver, which might cause spurious failures
# (this does not work unless ghost maps are doing the "use existing items if possible in get" optimization)

class MetadataPlugin(SimStatePlugin):
    UNIQUE_ID = claripy.BVS("metadata_unique_id", 1) # TODO: This should not need to exist...

    def __init__(self, items=None):
        SimStatePlugin.__init__(self)
        self.items = items or {}

    @SimStatePlugin.memo
    def copy(self, memo):
        return MetadataPlugin(items=copy.deepcopy(self.items))

    def items_copy(self): # for verification purposes
        return self.items.copy()

    def get_or_none(self, cls, key):
        return self.items.get(cls, {}).get(key.cache_key, None)

    def get(self, cls, key, default_ctor=None):
        value = self.get_or_none(cls, key)
        if value is None:
            if default_ctor is None:
                raise Exception(f"No metadata for key: {key} of class: {cls}")
            else:
                value = default_ctor()
                self.set(key, value)

        return value

    def get_all(self, cls):
        return {k.ast: v for (k, v) in self.items.get(cls, {}).items()}

    def get_unique(self, cls):
        all = self.get_all(cls)
        if len(all) == 0:
            return None
        if len(all) == 1:
            return next(iter(all.values()))
        raise Exception(f"No unique metadata for type {cls}")


    def set(self, key, value, override=False):
        cls = type(value)
        existing = self.get_or_none(cls, key)
        if existing is None:
            if override:
                raise Exception(f"There is no metadata of type {cls} to override for key {key}")
            map = self.items.setdefault(cls, {})
            map[key.cache_key] = value
        else:
            if not override:
                raise Exception(f"There is already metadata of type {cls} for key {key}, namely {existing}")
            self.items[cls][key.cache_key] = value


    def remove(self, cls, key):
        del self.items[cls][key.cache_key]

    def remove_all(self, cls):
        self.items.pop(cls, None) # pass the 2nd arg to not throw an error if cls not in items

    def clear(self):
        self.items = {}
