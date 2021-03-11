import claripy
from collections import namedtuple
import copy

from binary import bitsizes
from binary import utils
from . import spec_act
from . import spec_reg
from . import reg_util

# counter, use_init, latest_action are single-element lists so we can change them
SpecDevice = namedtuple('SpecDevice', ['phys_addr', 'virt_addr', 'bar_size', 'pci_regs', 'regs', 'counter', 'use_init', 'latest_action', 'legal_actions', 'actions'])

def spec_device_create_default(state):
    bar_size = 128 * 1024 # Intel 82599
    device = SpecDevice(claripy.BVS("dev_phys_addr", bitsizes.ptr), claripy.BVS("dev_virt_addr", bitsizes.ptr), bar_size, {}, {}, [0], [False], [None], copy.deepcopy(spec_act.device_init), {})
    utils.add_constraints_and_check_sat(state, device.phys_addr & 0b1111 == 0) # since the bottom 4 bits of the BAR are non-address stuff
    phys_addr_low = (device.phys_addr & 0xFFFFFFFF) | 0b0100
    phys_addr_high = device.phys_addr >> 32
    reg_util.update_reg(state, device.pci_regs, 'BAR0', None, spec_reg.pci_regs['BAR0'], phys_addr_low.reversed)
    reg_util.update_reg(state, device.pci_regs, 'BAR1', None, spec_reg.pci_regs['BAR1'], phys_addr_high.reversed) # TODO WHYYY REVERSED????
    return device