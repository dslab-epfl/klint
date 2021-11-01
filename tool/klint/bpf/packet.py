import claripy
from collections import namedtuple

from kalm import utils
from klint.bpf import detection
from klint.externals.net import packet as klint_packet # hacky; see remark in bpf/executor.py
from klint.ghostmaps import MapHas

BpfPacket = namedtuple('BpfPacket', ['addr'])

PACKET_MTU = 1514 # 1500 (Ethernet spec) + 2xMAC + EtherType

buff_data_offset = None
buff_dataend_offset = None
buff_rxq_offset = None
rxq_dev_offset = None
dev_ifindex_offset = None

def create(state, devices_count):
    global buff_data_offset, buff_dataend_offset, buff_rxq_offset, rxq_dev_offset, dev_ifindex_offset
    # 'struct xdp_md' is { u32 data, u32 data_end, u32 data_meta, u32 ingress_ifindex, u32 rx_queue_index, u32 egress_ifindex }
    # Except... not. The kernel doesn't actually passes a 'struct xdp_md' but a 'struct xdp_buff' (defined in Linux's `include/net/xdp.h`),
    # and rewrites code to map between the two. See `xdp_convert_ctx_access` in net/core/filter.c in Linux.
    # The xdp_md members are mapped with:
    # - data: data
    # - data_end: data_end
    # - data_meta: data_meta
    # - ingress_ifindex: rxq->dev->ifindex
    # - rx_queue_index: rxq->queue_index
    # - egress_ifindex: txq->dev->ifindex (in newer kernels only)
    # The 'fun' part is that these structures are kernel internals, thus they can and do change across releases...
    # so the best we can do is hardcode the offsets for specific releases.

    # For now let's only support {data, data_end, ingress_ifindex}.
    # This means we must have 'rxq' which must have a 'dev' which must have an 'ifindex'

    # If you're reading this because you got the exception below, what you need to do is:
    # - See what 'import platform; print(platform.release(), platform.architecture()[0])' returns on your system, and add an 'elif' case below
    # - Add information about the offsets in that case, which you can get either by compiling a BPF program that uses ifindex and dumping it,
    #   or by manually looking at Linux's 'include/net/xdp.h' and 'include/linux/netdevice.h', but don't forget to include padding...
    #   Note that offsets are in bytes!
    # - Once it works, send a pull request ;-)
    # NOTE: If these don't change across minor releases, it may be worth doing a substring check on the major version instead... do they change?
    linux_ver = detection.get_linux_version()
    if linux_ver is None:
        raise Exception("Looks like you're not running Linux. Sorry, no idea how BPF is even implemented on your platform...")
    elif linux_ver.startswith('5.4.0-81') and detection.is_64bit():
        buff_data_offset = 0
        buff_dataend_offset = 8
        buff_rxq_offset = 40
        rxq_dev_offset = 0
        dev_ifindex_offset = 264
    elif linux_ver.startswith('5.10') and detection.is_64bit():
        buff_data_offset = 0
        buff_dataend_offset = 8
        buff_rxq_offset = 32
        rxq_dev_offset = 0
        dev_ifindex_offset = 256
    else:
        raise Exception("Sorry, your specific kernel version is not supported. Adding support is easy, see instructions in " + __file__)

    # Generate a symbolic length that is at most the MTU. No minimum.
    data_length = claripy.BVS("data_length", state.sizes.ptr)
    state.solver.add(data_length.ULE(PACKET_MTU))

    # Generate a symbolic device. This is an u32 even on 64-bit systems.
    device = claripy.BVS("device", 32)
    state.solver.add(device.ULE(devices_count))

    # Allocate symbolic data
    data = state.heap.allocate(data_length, 1, ephemeral=True, name="data")

    # BPF programs assume they can do incorrect calculations like `data + offset > data_end` to check if `offset` is too far,
    # even though theoretically length could be 0 and data could be so high that `data + offset` overflows.
    # Let's say the data is at least a page before overflowing.
    state.solver.add(data.ULE(claripy.BVV(-4096, state.sizes.ptr)))

    # Now for the indirections... (only generate as much as we need, and leave the rest of the structs unconstrained just in case the program does funky things)
    dev = state.heap.allocate(1, dev_ifindex_offset + 4, ephemeral=True, name="rxq_dev")
    state.memory.store(dev + dev_ifindex_offset, device, endness=state.arch.memory_endness)
    rxq = state.heap.allocate(1, rxq_dev_offset + (state.sizes.ptr // 8), ephemeral=True, name="rxq")
    state.memory.store(rxq + rxq_dev_offset, dev, endness=state.arch.memory_endness)

    # Aaaand now we can actually create the xdp_buff.
    packet = state.heap.allocate(1, max(buff_data_offset, buff_dataend_offset, buff_rxq_offset) + (state.sizes.ptr // 8), ephemeral=True, name="xdp_buff")
    state.memory.store(packet + buff_data_offset, data, endness=state.arch.memory_endness)
    state.memory.store(packet + buff_dataend_offset, data + data_length, endness=state.arch.memory_endness)
    state.memory.store(packet + buff_rxq_offset, rxq, endness=state.arch.memory_endness)

    state.metadata.append(None, klint_packet.NetworkMetadata(data, 0, data_length, []))
    state.metadata.append(None, BpfPacket(packet))
    return packet

# bit of a hack so we can fetch it at the end...
def get_packet(state):
    return state.metadata.get_one(BpfPacket).addr

def get_data_and_end(state, packet):
    data = state.memory.load(packet + buff_data_offset, state.sizes.ptr // 8, endness=state.arch.memory_endness)
    data_end = state.memory.load(packet + buff_dataend_offset, state.sizes.ptr // 8, endness=state.arch.memory_endness)
    return (data, data_end)

def get_length(state, packet):
    (data, data_end) = get_data_and_end(state, packet)
    return data_end - data

def adjust_data_head(state, packet, delta):
    (data, data_end) = get_data_and_end(state, packet)
    length = data_end - data

    new_length = length - delta
    new_data = state.heap.allocate(new_length, 1, name="new_data")
    # This would be more accurate.
    # However, it runs into issues with buggy logic such as CRAB's,
    # which parses IP/TCP variable-length headers correctly but then ignores such parsing when copying headers over,
    # meaning the 'data' map has both the fixed-offset (incorrect) values and the variable-offset (correct) ones,
    # which requires complex constraints to model and kills performance...
    # Anyway, not doing so is sound, just not complete.
    #state.solver.add(state.maps.forall(data, lambda k, v: ~(k.SGE(delta)) | MapHas(new_data, k - delta, v)))

    state.memory.store(packet + buff_data_offset, new_data, endness=state.arch.memory_endness)
    state.memory.store(packet + buff_dataend_offset, new_data + new_length, endness=state.arch.memory_endness)
