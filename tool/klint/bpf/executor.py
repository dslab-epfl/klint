import angr
import claripy

from kalm import executor as kalm_executor
from kalm import utils
from klint.bpf import analysis
from klint.bpf import detection
from klint.bpf import externals
from klint.bpf import packet
from klint.externals.net import packet as klint_packet # hacky, but that way we share the verif (ideally this'd be in a shared folder somewhere...)
from klint.externals.net import tx as klint_tx # same
from klint import executor as klint_executor
from klint import statistics

def get_external(name):
    return getattr(externals, name)

def execute(code_path, calls_path, maps_path, maps_to_havoc, havoc_all):
    with open(code_path, 'rb') as code_file:
        code = code_file.read()

    blank = kalm_executor.create_blank_state(code)

    for (addr, name, map) in analysis.get_maps(maps_path, blank.sizes.ptr):
        externals.map_init(blank, addr, map, havoc_all or (name in maps_to_havoc))

    function = 0 # since our code is a single function
    exts = {a: get_external(n) for (a, n) in analysis.get_calls(calls_path)}

    devices_count = claripy.BVS("devices_count", 32)

    states, graphs = klint_executor.find_fixedpoint_states([(blank, lambda st: kalm_executor.create_calling_state(st, function, [packet.create(st, devices_count)], exts))])

    final_states = []
    results = []
    for state in states:
        cc = angr.DEFAULT_CC[state.project.arch.name](state.project.arch)
        result = state.casts.uint32_t(cc.get_return_val(state, stack_base=state.regs.sp - cc.STACKARG_SP_DIFF))
        results.append(result)
        # we're looking for result 3, XDP_TX
        const_result = utils.get_if_constant(state.solver, result)
        # doing this properly would require making metadata conditional; perfectly feasible, just not done yet
        if const_result is None:
            state_notx = state.copy()
            state_notx.solver.add(result != 3)
            if state_notx.solver.satisfiable():
                final_states.append(state_notx)
            state.solver.add(result == 3)
            if not state.solver.satisfiable():
                continue
            const_result = 3
        final_states.append(state)
        if const_result == 3:
            pkt = packet.get_packet(state)
            (data, data_end) = packet.get_data_and_end(state, pkt)
            metadata = state.metadata.get_one(klint_packet.NetworkMetadata)
            # no flags; not flood; pretend it's TX'd to dev0; no excluded devs
            metadata.transmitted.append(klint_tx.TransmissionMetadata(data, data_end - data, 0, False, 0, None))

    #print("BPF results", results)
    return final_states, devices_count, graphs
