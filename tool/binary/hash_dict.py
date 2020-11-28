from collections import OrderedDict

# Dictionary using hash identity, for e.g. Claripy ASTs
class HashDict:
    def __init__(self):
        self._items = OrderedDict()

    def __getitem__(self, key):
        return self._items.get(hash(key), (None, None))[1]

    def __setitem__(self, key, value):
        self._items[hash(key)] = (key, value)

    def __delitem__(self, key):
        del self._items[hash(key)]

    def __contains__(self, key):
        return hash(key) in self._items

    def __iter__(self):
        return self._items.values().__iter__()

    def __len__(self):
        return len(self._items)

    def __str__(self):
        return ", ".join(f"({k}, {v})" for (k, v) in self)

    def keys(self):
        return [k for (k, v) in self]

    def values(self):
        return [v for (k, v) in self]
