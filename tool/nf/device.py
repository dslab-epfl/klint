import claripy
from collections import namedtuple
import copy

from binary import bitsizes
from . import spec_act

# counter, use_init, latest_action are single-element lists so we can change them
SpecDevice = namedtuple('SpecDevice', ['phys_addr', 'virt_addr', 'pci_regs', 'regs', 'counter', 'use_init', 'latest_action', 'legal_actions', 'actions'])

def spec_device_create_default():
    return SpecDevice(claripy.BVS("dev_phys_addr", bitsizes.ptr), claripy.BVS("dev_virt_addr", bitsizes.ptr), {}, {}, [0], [False], [None], copy.deepcopy(spec_act.device_init), {})