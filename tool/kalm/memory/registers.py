import angr.storage.memory_mixins as csms
import claripy


# Memory used for registers.
# TODO make this faster by backing it with an array or such
class KalmRegistersMemory(
    csms.NameResolutionMixin,
    csms.DataNormalizationMixin,
    csms.SizeNormalizationMixin,
    csms.AddressConcretizationMixin,
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
