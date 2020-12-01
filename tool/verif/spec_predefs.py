# === SPEC PREDEFS === #

class LongestPrefixMatch:
    def __init__(self):
        self.lpm = lpm_alloc()

    def lookup(self, key):
        return lpm_lookup(self.lpm, key)

# === END SPEC PREDEFS === #