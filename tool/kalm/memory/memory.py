import angr.storage.memory_mixins as csms
import claripy

from kalm.memory.objects import ObjectsMemoryMixin


# Keep only what we need in the memory, including our custom layers
class KalmMemory(
    csms.NameResolutionMixin, # To allow uses of register names, which angr does internally when this is used for regs
    csms.DataNormalizationMixin, # To always get AST values
    csms.SizeNormalizationMixin, # To always get actual sizes in stores (required by some angr mixins)
    ObjectsMemoryMixin,
    # --- Rest is inspired by DefaultMemory, minus stuff we definitely don't need; TODO: can we make this all read-only after init?
    csms.ConvenientMappingsMixin,
    csms.StackAllocationMixin,
    csms.ClemoryBackerMixin,
    csms.DictBackerMixin,
    csms.UltraPagesMixin,
    csms.DefaultFillerMixin,
    csms.PagedMemoryMixin
):
    def _merge_values(self, values, merged_size):
        return claripy.ite_cases([(g, v) for (v, g) in values[1:]], values[0][0])