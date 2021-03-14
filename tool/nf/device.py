import angr
import claripy
from collections import namedtuple
import copy

from binary import bitsizes
from binary import utils
from . import spec_act
from . import spec_reg
from . import reg_util
from binary.exceptions import SymbexException

# counter, use_init, latest_action are single-element lists so we can change them
SpecDevice = namedtuple('SpecDevice', ['phys_addr', 'virt_addr', 'bar_size', 'pci_regs', 'regs', 'counter', 'use_init', 'latest_action', 'legal_actions', 'actions'])

def find_device(state, virt_addr):
    for dev in state.metadata.get_all(SpecDevice).values():
        if dev.virt_addr.structurally_match(virt_addr):
            return dev
    raise SymbexException("Unknown device")

def device_reader(state, base, _, offset):
    assert(_.op == 'BVV' and _.args[0] == 0)
    dev = find_device(state, base)
    reg, index = reg_util.find_reg_from_addr(state, offset // 8)
    reg_data = spec_reg.registers[reg]
    return reg_util.fetch_reg(dev.regs, reg, index, reg_data, dev.use_init[0])

def device_writer(state, base, _, offset, value):
    assert(_.op == 'BVV' and _.args[0] == 0)
    dev = find_device(state, base)
    reg, index = reg_util.find_reg_from_addr(state, offset // 8)
    reg_data = spec_reg.registers[reg]
    old_value = reg_util.fetch_reg(dev.regs, reg, index, reg_data, dev.use_init[0])
    fields = reg_util.find_fields_on_write(state, old_value, value, reg, spec_reg.registers)
    reg_util.check_access_write(old_value, value, reg, reg_data, fields)
    reg_util.verify_write(state, dev, fields, reg, index, spec_reg.registers)
    reg_util.update_reg(dev.regs, reg, index, reg_data, value)

    latest = dev.latest_action[0]
    if latest != None:
        # Apply postcondition
        post = dev.legal_actions[latest]['postcond']
        if post != None:
            post.applyAST(state, dev, index)
        dev.latest_action[0] = None


def spec_device_create_default(state):
    bar_size = 128 * 1024 # Intel 82599
    device = SpecDevice(claripy.BVS("dev_phys_addr", bitsizes.ptr), claripy.BVS("dev_virt_addr", bitsizes.ptr), bar_size, {}, {}, [0], [False], [None], copy.deepcopy(spec_act.device_init), {})

    # Phys addr handling
    utils.add_constraints_and_check_sat(state, device.phys_addr & 0b1111 == 0) # since the bottom 4 bits of the BAR are non-address stuff
    phys_addr_low = (device.phys_addr & 0xFFFFFFFF) | 0b0100
    phys_addr_high = device.phys_addr >> 32
    reg_util.update_reg(device.pci_regs, 'BAR0', None, spec_reg.pci_regs['BAR0'], phys_addr_low.reversed)
    reg_util.update_reg(device.pci_regs, 'BAR1', None, spec_reg.pci_regs['BAR1'], phys_addr_high.reversed) # TODO WHYYY REVERSED????

    # Virt addr handling
    state.memory.add_obj_handler(device.virt_addr, bar_size, device_reader, device_writer)

    return device