import angr
from angr.sim_type import *
import claripy
import datetime
import subprocess
import os

from kalm import utils
import kalm.clock as binary_clock
import kalm.executor as binary_executor
import klint.externals.net.packet
import klint.externals.net.tx
import klint.externals.os.clock
import klint.externals.os.config
import klint.externals.os.log
import klint.externals.os.memory
import klint.externals.os.pci
import klint.externals.structs.cht
import klint.externals.structs.index_pool
import klint.externals.structs.lpm
import klint.externals.structs.map
import klint.externals.verif.verif
import klint.fullstack
import klint.ghostmaps
from klint import statistics


structs_alloc_externals = {
    'map_alloc': klint.externals.structs.map.map_alloc,
    'index_pool_alloc': klint.externals.structs.index_pool.index_pool_alloc,
    'cht_alloc': klint.externals.structs.cht.ChtAlloc,
    'lpm_alloc': klint.externals.structs.lpm.LpmAlloc,
}

structs_functions_externals = {
    'map_get': klint.externals.structs.map.map_get,
    'map_set': klint.externals.structs.map.map_set,
    'map_remove': klint.externals.structs.map.map_remove,
    'index_pool_borrow': klint.externals.structs.index_pool.index_pool_borrow,
    'index_pool_return': klint.externals.structs.index_pool.index_pool_return,
    'index_pool_refresh': klint.externals.structs.index_pool.index_pool_refresh,
    'index_pool_used': klint.externals.structs.index_pool.index_pool_used,
    'cht_find_preferred_available_backend': klint.externals.structs.cht.ChtFindPreferredAvailableBackend,
    'lpm_set': klint.externals.structs.lpm.LpmSet,
    'lpm_search': klint.externals.structs.lpm.LpmSearch,
    'lpm_remove': klint.externals.structs.lpm.LpmRemove,
}


# graph_handler instead of returning graphs so we can get intermediary graphs even if there's later a crash or hang
def find_fixedpoint_states(states_data, ret_width=None, existing_results=None, graph_handler=None):
    # HACK: Allow callers to pass existing_results, for BPF map havocing...
    inference_results = existing_results
    while True:
        print("Running an iteration of the main loop at", datetime.datetime.now())
        statistics.work_start("symbex")
        result_states = []
        for (state, state_fun) in states_data:
            starting_state = state_fun(state.copy())
            states, graph = binary_executor.run_state(starting_state, ret_width=ret_width)
            result_states += states
            if graph_handler is not None:
                graph_handler(graph)
        statistics.work_end()
        print("Inferring invariants on", len(result_states), "states at", datetime.datetime.now())
        states = [s for (s, _) in states_data]
        statistics.work_start("infer")
        (states, inference_results, reached_fixpoint) = klint.ghostmaps.infer_invariants(states, result_states, inference_results)
        statistics.work_end()
        if reached_fixpoint:
            return result_states
        states_data = [(new_s, fun) for (new_s, (old_s, fun)) in zip(states, states_data)]


# === libNF ===

libnf_init_externals = {
    'os_config_try_get': klint.externals.os.config.os_config_try_get,
    'os_memory_alloc': klint.externals.os.memory.os_memory_alloc
}
libnf_init_externals.update(structs_alloc_externals)

libnf_handle_externals = {
    'os_debug': klint.externals.os.log.os_debug,
    'net_transmit': klint.externals.net.tx.net_transmit,
    'net_flood': klint.externals.net.tx.net_flood,
    'net_flood_except': klint.externals.net.tx.net_flood_except
}
libnf_handle_externals.update(structs_functions_externals)

def get_libnf_inited_states(binary_path, devices_count):
    blank_state = binary_executor.create_blank_state(binary_path)
    # Create and run an init state
    init_state = binary_executor.create_calling_state(blank_state, "nf_init", SimTypeFunction([SimTypeNum(16, False)], SimTypeBool()), [devices_count], libnf_init_externals)
    init_state.solver.add(devices_count.UGT(0))
    statistics.work_start("symbex")
    # ignore the graph here, not useful
    result_states, _ = binary_executor.run_state(init_state)
    statistics.work_end()
    # Create handle states from all successful inits
    inited_states = []
    for state in result_states:
        init_result = utils.get_ret_val(state, 8) # ret val is a bool so we only care about 1 byte
        state.solver.add(init_result != 0)
        if state.solver.satisfiable():
            state.path.clear() # less noise when debugging
            state_creator = lambda st: binary_executor.create_calling_state(st, "nf_handle", SimTypeFunction([SimTypePointer(SimTypeBottom(label="void"))], None), [klint.externals.net.packet.alloc(st, devices_count)], libnf_handle_externals)
            inited_states.append((state, state_creator))
    return inited_states

def execute_libnf(binary_path, graph_handler=None):
    print("libNF symbex starting at", datetime.datetime.now())
    devices_count = claripy.BVS('devices_count', 16) # TODO avoid the hardcoded 16 here
    inited_states = get_libnf_inited_states(binary_path, devices_count)
    result_states = find_fixedpoint_states(inited_states, ret_width=0, graph_handler=graph_handler) # ret_width=0 cause no return value in libnf's main
    print("libNF symbex done at", datetime.datetime.now())
    return (result_states, devices_count) # TODO devices_count should be in metadata somewhere, not explicitly returned


# === Full-stack ===

nf_init_externals = {
    'os_clock_sleep_ns': klint.externals.os.clock.os_clock_sleep_ns,
    'os_config_try_get': klint.externals.os.config.os_config_try_get,
    'os_memory_alloc': klint.externals.os.memory.os_memory_alloc,
    'os_memory_phys_to_virt': klint.externals.os.memory.os_memory_phys_to_virt,
    'os_memory_virt_to_phys': klint.externals.os.memory.os_memory_virt_to_phys,
    'os_pci_enumerate': klint.externals.os.pci.os_pci_enumerate,
    'descriptor_ring_alloc': klint.externals.verif.verif.descriptor_ring_alloc,
    'agents_alloc': klint.externals.verif.verif.agents_alloc,
    'foreach_index_forever': klint.externals.verif.verif.foreach_index_forever
}
nf_init_externals.update(structs_alloc_externals)

nf_handle_externals = structs_functions_externals

nf_inited_states = [] # "global" for use in externals/verif/verif.py
def execute_nf(binary_path):
    print("NF symbex starting at", datetime.datetime.now())
    klint.fullstack.spec_reg.validate_registers(klint.fullstack.spec_reg.registers)
    klint.fullstack.spec_reg.validate_registers(klint.fullstack.spec_reg.pci_regs)
    klint.fullstack.spec_act.validate_actions()
    blank_state = binary_executor.create_blank_state(binary_path)
    init_state = binary_executor.create_calling_state(blank_state, "_start", SimTypeFunction([], None), [], nf_init_externals)
    global nf_inited_states
    assert nf_inited_states is not None
    nf_inited_states = []
    statistics.work_start("symbex")
    binary_executor.run_state(init_state, allow_trap=True) # this will fill nf_inited_states; we allow traps only here since that's how init can fail
    statistics.work_end()
    assert len(nf_inited_states) > 0
    result_states = find_fixedpoint_states(nf_inited_states)
    print("NF symbex done at", datetime.datetime.now())
    return (result_states, claripy.BVV(2, 16)) # TODO ouch hardcoding, same remark as in execute_libnf
