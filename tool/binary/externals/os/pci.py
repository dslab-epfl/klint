# Standard/External libraries
import angr
import claripy

# Us
from ... import bitsizes
from ... import cast

# size_t os_pci_enumerate(struct os_pci_address** out_devices);
class os_pci_enumerate(angr.SimProcedure):
    def run(self, out_devices):
        out_devices = cast.ptr(out_devices)

        count = claripy.BVS("pci_devices_count", bitsizes.size_t)
        devices = self.state.memory.allocate(count, 8, name="pci_devices") # 8 == sizeof(os_pci_address)
        self.state.memory.store(out_devices, devices, endness=self.state.arch.memory_endness)
        return count

# uint32_t os_pci_read(struct os_pci_address address, uint8_t reg);
class os_pci_read(angr.SimProcedure):
    def run(self, address, reg):
        address = cast.struct(address)
        reg = cast.uint8_t(reg)
        ...

# void os_pci_write(struct os_pci_address address, uint8_t reg, uint32_t value);
class os_pci_write(angr.SimProcedure):
    def run(self, address, reg, value):
        address = cast.struct(address)
        reg = cast.uint8_t(reg)
        value = cast.uint32_t(value)
        ...