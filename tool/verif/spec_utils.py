# This file is prefixed to all specifications.
# It contains helpers that are not key to specifications but may be useful for some of them.

# TODO: Ideally, the tool would be able to infer that A->B and B->C maps can be treated as an A->C map,
# and then this class could disappear and just have the 'full' inlined into the specs...
class ExpiringSet:
    def __init__(self, elem_type, expiration_time, capacity, _elems_to_indices=None, _indices_to_times=None):
        self.elem_type = elem_type
        self.expiration_time = expiration_time
        self.capacity = capacity
        self._elems_to_indices = _elems_to_indices or Map(elem_type, "size_t")
        self._indices_to_times = _indices_to_times or Map("size_t", "uint64_t")

    @property
    def old(self):
        return ExpiringSet(self.elem_type, self.expiration_time, self.capacity, self._elems_to_indices.old, self._indices_to_times.old)

    @property
    def full(self):
        return (self._elems_to_indices.length == self.capacity) & \
               (time() < self.expiration_time | self._indices_to_times.forall(lambda k, v: v >= (time() - self.expiration_time)))

    def __contains__(self, item):
        return item in self._elems_to_indices