# === SPEC PREDEFS === #

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