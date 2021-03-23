# Standard/External libraries
import angr
import claripy
from collections import namedtuple

# Us
from ... import bitsizes
from ... import cast
from ... import utils
from ...exceptions import SymbexException
from nf.device import *
from nf import spec_reg
from nf import reg_util

PciDevices = namedtuple('PciDevices', ['ptr', 'count'])

# TODO the uses of .reversed in this file are driving me nuts, really need to move to the latest memory model...

def get_device(state, bus, device, function):
    meta = state.metadata.get_unique(PciDevices)
    index = claripy.BVS("pci_index", bitsizes.size_t)
    utils.add_constraints_and_check_sat(state, index.ULT(meta.count))
    value = state.memory.load(meta.ptr + index * 8, 8).reversed # 8 == sizeof(os_pci_address)
    value_bus = value[7:0] # this is kind of .reversed since it should be 63:56! same for the others
    value_device = value[15:8]
    value_function = value[23:16]
    utils.add_constraints_and_check_sat(state, bus == value_bus, device.zero_extend(3) == value_device, function.zero_extend(5) == value_function)
    index = state.solver.eval_one(index, cast_to=int) # technically not needed?
    return state.metadata.get(SpecDevice, index, default_ctor=lambda: spec_device_create_default(state, index))

def pci_read(state, address):
    (b, d, f, reg) = address
    device = get_device(state, b, d, f)
    reg_concrete = state.solver.eval_one(reg, cast_to=int)
    reg_name = reg_util.get_pci_reg(reg_concrete, spec_reg.pci_regs)
    reg_data = spec_reg.pci_regs[reg_name]
    return reg_util.fetch_reg(device.pci_regs, reg_name, None, reg_data, True) # no index, and use_init always True for PCI reads

def pci_write(state, address, value):
    (b, d, f, reg) = address
    device = get_device(state, b, d, f)
    reg_concrete = state.solver.eval_one(reg, cast_to=int)
    reg_name = reg_util.get_pci_reg(reg_concrete, spec_reg.pci_regs)
    reg_data = spec_reg.pci_regs[reg_name]
    old_value = reg_util.fetch_reg(device.pci_regs, reg_name, None, reg_data, True)
    fields = reg_util.find_fields_on_write(state, old_value, value, reg_name, spec_reg.pci_regs)
    reg_util.check_access_write(old_value, value, reg_name, reg_data, fields)
    reg_util.verify_write(state, device, fields, reg_name, None, spec_reg.pci_regs)
    reg_util.update_reg(device.pci_regs, reg_name, None, reg_data, value)



# size_t os_pci_enumerate(struct os_pci_address** out_devices);
class os_pci_enumerate(angr.SimProcedure):
    def run(self, out_devices):
        out_devices = cast.ptr(out_devices)

        self.state.pci.set_handlers(pci_read, pci_write)
        count = claripy.BVV(2, bitsizes.size_t) #TODO: claripy.BVS("pci_devices_count", bitsizes.size_t), but then how do we ensure they're unique?

        meta = self.state.metadata.get_all(PciDevices)
        if len(meta) == 0:
            utils.add_constraints_and_check_sat(self.state, count.ULT(256 * 32 * 8)) # 256 buses, 32 devices, 8 functions
            meta = PciDevices(
                self.state.memory.allocate(count, 8, name="pci_devices", constraint=lambda k, v: (v.reversed & 0x00_E0_F8_FFFFFFFFFF) == 0), # 8 == sizeof(os_pci_address); enforce constraints on B/D/F and padding
                count
            )
            self.state.metadata.set(None, meta)
            # ouch! TODO we need to do better... see above if count were to be symbolic
            utils.add_constraints_and_check_sat(self.state, self.state.memory.load(meta.ptr + 0 * 8, 8) != self.state.memory.load(meta.ptr + 1 * 8, 8))
        else:
            meta = meta.values()[0]

        self.state.memory.store(out_devices, meta.ptr, endness=self.state.arch.memory_endness)
        return meta.count
