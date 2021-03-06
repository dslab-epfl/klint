import angr
from angr.sim_type import *
import claripy

from kalm import utils
import klint.fullstack.device as nf_device


# void* os_memory_alloc(size_t count, size_t size);
# requires count == 1 || count * size <= SIZE_MAX;
# ensures uchars(result, count * size, ?cs) &*& true == all_eq(cs, 0) &*& result + count * size <= (char*) UINTPTR_MAX &*&
#         result != NULL &*& (size_t) result % (size + CACHE_LINE_SIZE - (size % CACHE_LINE_SIZE)) == 0;
class os_memory_alloc(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypeLength(False), SimTypeLength(False)], SimTypePointer(SimTypeBottom(label="void")), arg_names=["count", "size"])

    def run(self, count, size):
        # Symbolism assumptions
        if size.symbolic:
            raise Exception("size cannot be symbolic")

        # Preconditions (zero-extend to check correctly for overflows)
        assert utils.definitely_true(self.state.solver,
            (count == 1) | ((count.zero_extend(self.state.sizes.size_t) * size.zero_extend(self.state.sizes.size_t)) <= (2 ** self.state.sizes.size_t - 1))
        )

        # Postconditions
        # Non-null is already done in heap.allocate
        result = self.state.heap.allocate(count, size, name="allocated", default=claripy.BVV(0, self.state.solver.eval_one(size, cast_to=int) * 8))

        # Optimization: Avoid use of a symbolic modulo
        multiplier = claripy.BVS("memory_mult", self.state.sizes.ptr)
        self.state.solver.add(result == multiplier * (size + 64 - (size % 64)))
        print("!!! os_memory_alloc", count, size, "->", result)
        return result

# void* os_memory_phys_to_virt(uintptr_t addr, size_t size);
class os_memory_phys_to_virt(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypeLength(False), SimTypeLength(False)], SimTypePointer(SimTypeBottom(label="void")), arg_names=["addr", "size"])

    def run(self, addr, size):
        assert len(addr.variables) == 1
        original_addr = claripy.BVS(next(iter(addr.variables)), addr.size(), explicit_name=True)
        if utils.can_be_false(self.state.solver, addr == original_addr):
            raise Exception("Sorry, expected an addr as a BAR0 high-low pair")

        devices = self.state.metadata.get_all(nf_device.SpecDevice)
        for dev in devices.values():
            if utils.definitely_true(self.state.solver, original_addr == dev.phys_addr):
                if utils.can_be_true(self.state.solver, size.UGT(dev.bar_size)):
                    raise Exception("Requested size is too big")
                return dev.virt_addr

        raise Exception("IDK what phys addr that is, sorry")

# uintptr_t os_memory_virt_to_phys(const void* addr);
class os_memory_virt_to_phys(angr.SimProcedure):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prototype = SimTypeFunction([SimTypePointer(SimTypeBottom(label="void"))], SimTypeLength(False), arg_names=["addr"])

    def run(self, addr):
        return addr # TODO proper handling
