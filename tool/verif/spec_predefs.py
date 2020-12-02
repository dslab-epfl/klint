# === SPEC PREDEFS === #

class Array:
    def __init__(self, length, type):
        self._type = type
        self._size = type_size(type)
        self._addr = os_memory_alloc(length, self._size)

    def __getitem__(self, index):
        return ptr_read(self._addr + (index * self._size), self._type)


class ExpiringSet:
    def __init__(self, max_capacity, type):
        self._value_size = type_size(type)
        self._values = os_memory_alloc(max_capacity, self._value_size)
        self._map = os_map_alloc(self._value_size, max_capacity)
        self._pool = os_pool_alloc(max_capacity)

    def get(self, item, time):
        index_ptr = ptr_alloc("size_t")
        has = os_map_get(self._map, item, index_ptr)
        if has:
            os_pool_refresh(self._pool, time, ptr_read(index_ptr))
            return self._values + (ptr_read(index_ptr) * self._value_size)
        return None

    def try_add(self, item, time):
        index_ptr = ptr_alloc("size_t")
        if os_pool_expire(self._pool, time, index_ptr):
            os_map_remove(self._map, self._values + (ptr_read(index_ptr) * self._value_size))
        ok = os_pool_borrow(self._pool, time, index_ptr)
        if ok:
            index = ptr_read(index_ptr)
            ptr_write(self._values + (index * self._value_size), item)
            os_map_set(self._map, self._values + (index * self._value_size), index)
        return ok


class LongestPrefixMatch:
    def __init__(self):
        self.lpm = lpm_alloc()

    def lookup(self, key):
        out_value = ptr_alloc("uint16_t")
        out_prefix = ptr_alloc("uint32_t")
        out_prefixlen = ptr_alloc("uint8_t")
        has = lpm_lookup_elem(self.lpm, key, out_value, out_prefix, out_prefixlen)
        if has:
            return ptr_read(out_value)
        return None

# === END SPEC PREDEFS === #