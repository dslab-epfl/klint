import claripy
import platform

from kalm import executor as kalm_executor
from klint.bpf import analysis
from klint.bpf import externals

PACKET_MTU = 1514 # 1500 (Ethernet spec) + 2xMAC + EtherType

def get_linux_version():
    if platform.system() != 'Linux':
        return None
    return platform.release()

def is_64bit():
    # https://stackoverflow.com/a/12578715
    return platform.machine().endswith('64')

def get_external(name):
    return getattr(externals, name)

def create_arg(state):
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
    linux_ver = get_linux_version()
    if linux_ver is None:
        raise Exception("Looks like you're not running Linux. Sorry, no idea how BPF is even implemented on your platform...")
    elif linux_ver == '5.4.0-81-generic' and is_64bit():
        buff_data_offset = 0
        buff_dataend_offset = 8
        buff_rxq_offset = 40
        rxq_dev_offset = 0
        dev_ifindex_offset = 264
    else:
        raise Exception("Sorry, your specific kernel version is not supported. Adding support is easy, see instructions in " + __file__)

    # Generate a symbolic length that is at most the MTU. No minimum.
    packet_length = claripy.BVS("packet_length", state.sizes.ptr)
    state.solver.add(packet_length.ULE(PACKET_MTU))

    # Generate a symbolic device. No constraints. This is an u32 even on 64-bit systems.
    packet_device = claripy.BVS("packet_device", 32)

    # Allocate a symbolic packet
    packet = state.heap.allocate(packet_length, 1, name="packet")

    # BPF programs assume they can do incorrect calculations like `data + offset > data_end` to check if `offset` is too far,
    # even though theoretically length could be 0 and data could be so high that `data + offset` overflows.
    # Let's say the packet is at least a page before overflowing.
    state.solver.add(packet.ULE(claripy.BVV(-4096, state.sizes.ptr)))

    # Now for the indirections... (only generate as much as we need, and leave the rest of the structs unconstrained just in case the program does funky things)
    dev = state.heap.allocate(1, dev_ifindex_offset + 4, name="rxq_dev")
    state.memory.store(dev + dev_ifindex_offset, packet_device, endness=state.arch.memory_endness)
    rxq = state.heap.allocate(1, rxq_dev_offset + (state.sizes.ptr // 8), name="rxq")
    state.memory.store(rxq + rxq_dev_offset, dev, endness=state.arch.memory_endness)

    # Aaaand now we can actually create the xdp_buff.
    buff = state.heap.allocate(1, max(buff_data_offset, buff_dataend_offset, buff_rxq_offset) + (state.sizes.ptr // 8), name="xdp_buff")
    state.memory.store(buff + buff_data_offset, packet, endness=state.arch.memory_endness)
    state.memory.store(buff + buff_dataend_offset, packet + packet_length, endness=state.arch.memory_endness)
    state.memory.store(buff + buff_rxq_offset, rxq, endness=state.arch.memory_endness)
    return buff


def execute(code_path, calls_path, maps_path):
    with open(code_path, 'rb') as code_file:
        code = code_file.read()
        blank = kalm_executor.create_blank_state(code)
        for (addr, map) in analysis.get_maps(maps_path, blank.sizes.ptr):
            externals.map_init(blank, addr, map)
        function = 0 # since our code is a single function
        function_args = [create_arg(blank)]
        exts = {a: get_external(n) for (a, n) in analysis.get_calls(calls_path)}
        calling = kalm_executor.create_calling_state(blank, function, function_args, exts)
        kalm_executor.run_state(calling)
