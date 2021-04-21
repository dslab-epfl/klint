import angr
import claripy
from collections import namedtuple
import copy

from binary import utils
from . import spec_act
from . import spec_reg
from . import reg_util
from binary.externals.net import packet # ouch

# counter, use_init, latest_action are single-element lists so we can change them
SpecDevice = namedtuple('SpecDevice', ['index', 'phys_addr', 'virt_addr', 'bar_size', 'pci_regs', 'regs', 'counter', 'use_init', 'latest_action', 'actions', 'packet_length', 'packet_data'])

def find_device(state, virt_addr):
    for dev in state.metadata.get_all(SpecDevice).values():
        if dev.virt_addr.structurally_match(virt_addr):
            return dev
    raise Exception("Unknown device")

def get_device(state, index):
    devs = [d for d in state.metadata.get_all(SpecDevice).values() if d.index.structurally_match(index)]
    assert len(devs) == 1
    return devs[0]

def get_rdba_0(dev):
    reg_index = 0
    rdbal = dev.regs["RDBAL"][reg_index].zero_extend(32)
    rdbah = dev.regs["RDBAH"][reg_index].zero_extend(32)
    return (rdbah << 32) | rdbal

def receive_packet_on_device(state, index):
    dev = get_device(state, index)
    # TODO should check RDT here (>0)
    rdba = get_rdba_0(dev)
    # TODO virt2phys handling
    # TODO use buffer_length = dev.regs["SRRCTL"][reg_index][4:0].zero_extend(state.sizes.size_t - 5) * 1024
    packet_addr = state.memory.load(rdba, 8, endness=state.arch.memory_endness)
    state.memory.store(packet_addr, dev.packet_data, endness=state.arch.memory_endness)

    packet_desc_meta = dev.packet_length.zero_extend(64 - dev.packet_length.size()) | (0b11 << 32) # DD and EOP, plus length
    state.memory.store(rdba + 8, packet_desc_meta, endness=state.arch.memory_endness)
    # TODO should update RDH here (+1)

    state.metadata.append(packet_addr, packet.NetworkMetadata(dev.packet_data, packet_addr, dev.index, dev.packet_length, []))


def device_reader(state, base, index, offset, size):
    assert index.structurally_match(claripy.BVV(0, index.size()))
    assert size is None or size == 4
    dev = find_device(state, base)
    reg, index = reg_util.find_reg_from_addr(state, offset // 8)
    reg_data = spec_reg.registers[reg]
    return reg_util.fetch_reg(dev.regs, reg, index, reg_data, dev.use_init[0])

def device_writer(state, base, index, offset, value):
    assert index.structurally_match(claripy.BVV(0, index.size()))
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
        if utils.can_be_true(state.solver, packet_length != 0):
            print("TDT len is not zero!")
            metadata = state.metadata.get_one(packet.NetworkMetadata)
            metadata.transmitted.append((packet_data, packet_length, dev.index, None))


def spec_device_create_default(state, index):
    bar_size = 128 * 1024 # Intel 82599

    # Virt addr handling
    virt_addr = state.memory.create_special_object("dev_virt_addr", claripy.BVV(1, state.sizes.size_t), bar_size, device_reader, device_writer)

    # Phys addr handling
    phys_addr = claripy.BVS("dev_phys_addr", state.sizes.ptr)
    state.solver.add(phys_addr & 0b1111 == 0) # since the bottom 4 bits of the BAR are non-address stuff

    packet_length = claripy.BVS("packet_len", state.sizes.size_t) # TODO how to enforce packet_length here?
    state.solver.add(packet_length.UGE(packet.PACKET_MIN), packet_length.ULE(packet.PACKET_MTU))
    packet_data = claripy.BVS("packet_data", packet.PACKET_MTU * 8)

    device = SpecDevice(index, phys_addr, virt_addr, bar_size, {}, {}, [0], [False], [None], {}, packet_length, packet_data)

    # Single 64-bit BAR as per data sheet
    phys_addr_low = (phys_addr & 0xFFFFFFFF) | 0b0100
    phys_addr_high = phys_addr >> 32
    reg_util.update_reg(device.pci_regs, 'BAR0', None, spec_reg.pci_regs['BAR0'], phys_addr_low)
    reg_util.update_reg(device.pci_regs, 'BAR1', None, spec_reg.pci_regs['BAR1'], phys_addr_high)

    return device