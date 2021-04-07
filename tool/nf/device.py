import angr
import claripy
from collections import namedtuple
import copy

from binary import bitsizes
from binary import utils
from . import spec_act
from . import spec_reg
from . import reg_util
from binary.externals.net import packet # ouch

# counter, use_init, latest_action are single-element lists so we can change them
SpecDevice = namedtuple('SpecDevice', ['index', 'phys_addr', 'virt_addr', 'bar_size', 'pci_regs', 'regs', 'counter', 'use_init', 'latest_action', 'actions'])

def find_device(state, virt_addr):
    for dev in state.metadata.get_all(SpecDevice).values():
        if dev.virt_addr.structurally_match(virt_addr):
            return dev
    raise Exception("Unknown device")

def device_reader(state, base, offset):
    dev = find_device(state, base)
    reg, index = reg_util.find_reg_from_addr(state, offset // 8)
    reg_data = spec_reg.registers[reg]
    return reg_util.fetch_reg(dev.regs, reg, index, reg_data, dev.use_init[0])

def device_writer(state, base, offset, value):
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
        post = spec_act.actions[latest]['postcond']
        if post != None:
            post.applyAST(state, dev, index)
        dev.latest_action[0] = None

    # Special action for RDT, let's receive a packet
    if reg == "RDT":
        rdbal = dev.regs["RDBAL"][index].zero_extend(32)
        rdbah = dev.regs["RDBAH"][index].zero_extend(32)
        rdba = (rdbah << 32) | rdbal
        # TODO virt2phys handling
        buffer_length = dev.regs["SRRCTL"][index][4:0].zero_extend(bitsizes.size_t - 5) * 1024
        packet_length = claripy.BVS("packet_len", bitsizes.size_t) # TODO how to enforce packet_length here?
        packet_addr = state.memory.load(rdba, 8, endness=state.arch.memory_endness)
        packet_data = state.memory.allocate(1, packet.PACKET_MTU, name="packet_data")
        packet_desc_meta = packet_length.zero_extend(64 - packet_length.size()) | (0b11 << 32) # DD and EOP, plus length

        state.solver.add(packet_length.UGE(packet.PACKET_MIN), packet_length.ULE(packet.PACKET_MTU))
        state.metadata.set(packet_addr, packet.NetworkMetadata(packet_data, packet_addr, dev.index, packet_length, []))

        state.memory.store(packet_addr, packet_data, endness=state.arch.memory_endness)
        state.memory.store(rdba + 8, packet_desc_meta, endness=state.arch.memory_endness)

    # Special action for TDT, we're sending a packet
    if reg == "TDT":
        tdbal = dev.regs["TDBAL"][index].zero_extend(32)
        tdbah = dev.regs["TDBAH"][index].zero_extend(32)
        tdba = (tdbah << 32) | tdbal
        # TODO virt2phys handling
        packet_addr = state.memory.load(tdba, 8, endness=state.arch.memory_endness)
        packet_data = state.memory.load(packet_addr, packet.PACKET_MTU, endness=state.arch.memory_endness)
        packet_desc_meta = state.memory.load(tdba + 8, 8, endness=state.arch.memory_endness)

        if utils.can_be_true(state.solver, packet_desc_meta[25:24] != claripy.BVV(3, 2)):
            raise Exception("May not have EOP or DD flags")

        packet_length = packet_desc_meta[15:0]


def spec_device_create_default(state, index):
    bar_size = 128 * 1024 # Intel 82599
    device = SpecDevice(index, claripy.BVS("dev_phys_addr", bitsizes.ptr), claripy.BVS("dev_virt_addr", bitsizes.ptr), bar_size, {}, {}, [0], [False], [None], {})

    # Phys addr handling
    state.solver.add(device.phys_addr & 0b1111 == 0) # since the bottom 4 bits of the BAR are non-address stuff
    phys_addr_low = (device.phys_addr & 0xFFFFFFFF) | 0b0100
    phys_addr_high = device.phys_addr >> 32
    reg_util.update_reg(device.pci_regs, 'BAR0', None, spec_reg.pci_regs['BAR0'], phys_addr_low)
    reg_util.update_reg(device.pci_regs, 'BAR1', None, spec_reg.pci_regs['BAR1'], phys_addr_high)

    # Virt addr handling
    state.memory.add_obj_handler(device.virt_addr, bar_size, device_reader, device_writer)

    return device