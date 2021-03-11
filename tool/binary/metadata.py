# Standard/External libraries
import angr
import claripy
from angr.state_plugins.plugin import SimStatePlugin
import copy

# Us
from . import utils
from .hash_dict import HashDict
from .exceptions import SymbexException

# TODO can we specialize this class? remove it? use ghost maps directly instead somehow (eg an enum for IDs)?

# Optimization: objects are compared structurally instead of with the solver, which might cause spurious failures
# (this does not work unless ghost maps are doing the "use existing items if possible in get" optimization)

class MetadataPlugin(SimStatePlugin):
    def __init__(self, items=None):
        SimStatePlugin.__init__(self)
        self.items = items or {}

    @SimStatePlugin.memo
    def copy(self, memo):
        return MetadataPlugin(items=copy.deepcopy(self.items))

    def items_copy(self): # for verification purposes
        return self.items.copy()

    def _get_value(self, cls, key):
        map = self.items.get(cls, None)
        if map is None:
            return None
        return map[key]


    def get(self, cls, key, default_ctor=None):
        value = self._get_value(cls, key)
        if value is None:
            if default_ctor is None:
                raise SymbexException(f"No metadata for key: {key} of class: {cls}")
            else:
                value = default_ctor()
                self.set(key, value)

        return value


    def get_all(self, cls):
        return self.items.get(cls, HashDict())

    def get_unique(self, cls):
        all = self.get_all(cls)
        if len(all) == 0:
            return None
        if len(all) == 1:
            return all.values()[0]
        raise SymbexException(f"No unique metadata for type {cls}")


    def set(self, key, value, override=False):
        cls = type(value)
        existing = self._get_value(cls, key)
        if existing is None:
            if override:
                raise SymbexException(f"There is no metadata of type {cls} to override for key {key}")
            map = self.items.get(cls, None)
            if map is None:
                map = HashDict()
                self.items[cls] = map
            map[key] = value
        else:
            if not override:
                raise SymbexException(f"There is already metadata of type {cls} for key {key}, namely {existing}")
            self.items[cls][key] = value


    def remove(self, cls, key):
        del self.items[cls][key]

    def remove_all(self, cls):
        if cls in self.items:
            del self.items[cls]

    def clear(self):
        self.items = {}
