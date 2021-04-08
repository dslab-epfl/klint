# This file is included before every specification, it contains common helpers

class ExpiringSet:
    def __init__(self, elem_type, expiration_time, capacity):
        self.expiration_time = expiration_time
        self.capacity = capacity
        self._elems_to_indices = Map(elem_type, "size_t")
        self._indices_to_times = Map("size_t", "time_t")

    def full(self):
        return (self._elems_to_indices.length() == self.capacity) & \
               (time() < self.expiration_time | self._indices_to_times.forall(lambda k, v: v >= time() - self.expiration_time))

    def __contains__(self, item):
        return item in self.elems_to_indices