import angr
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
import klint.externals.havoc
import klint.fullstack
import klint.ghostmaps
from klint import statistics


structs_alloc_externals = {
    'map_alloc': klint.externals.structs.map.map_alloc,
    'index_pool_alloc': klint.externals.structs.index_pool.index_pool_alloc,
    'cht_alloc': klint.externals.structs.cht.ChtAlloc,
    'lpm_alloc': klint.externals.structs.lpm.LpmAlloc,
    # these are a hack for Katran, not something that should exist; anyway they're not in any header
    'klint_havoc_array': klint.externals.havoc.klint_havoc_array,
    'klint_havoc_hashmap': klint.externals.havoc.klint_havoc_hashmap
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
    'lpm_lookup_elem': klint.externals.structs.lpm.LpmLookupElem,
    'lpm_update_elem': klint.externals.structs.lpm.LpmUpdateElem
}


def find_fixedpoint_states(states_data):
    inference_results = None
    result_graphs = []
    while True:
        print("Running an iteration of the main loop at", datetime.datetime.now())
        statistics.work_start("symbex")
        result_states = []
        for (state, state_fun) in states_data:
            starting_state = state_fun(state.copy())
            states, graph = binary_executor.run_state(starting_state)
            result_states += states
            result_graphs.append(graph)
        statistics.work_end()
        print("Inferring invariants on", len(result_states), "states at", datetime.datetime.now())
        states = [s for (s, _) in states_data]
        statistics.work_start("infer")
        (states, inference_results, reached_fixpoint) = klint.ghostmaps.infer_invariants(states, result_states, inference_results)
        statistics.work_end()
        if reached_fixpoint:
            return (result_states, result_graphs)
        states_data = [(new_s, fun) for (new_s, (old_s, fun)) in zip(states, states_data)]


# === libNF ===

libnf_init_externals = {
    'os_config_try_get': klint.externals.os.config.os_config_try_get,
    'os_memory_alloc': klint.externals.os.memory.os_memory_alloc
}
libnf_init_externals.update(structs_alloc_externals)

libnf_handle_externals = {
    'os_debug': klint.externals.os.log.os_debug,
    'os_debug2': klint.externals.os.log.os_debug2,
    'net_transmit': klint.externals.net.tx.net_transmit,
    'net_flood': klint.externals.net.tx.net_flood,
    'net_flood_except': klint.externals.net.tx.net_flood_except
}
libnf_handle_externals.update(structs_functions_externals)

# subprocess.check_call(["make", "-f" "../Makefile.nf"], cwd=nf_folder) TODO also for full-stack
def get_libnf_inited_states(binary_path, devices_count):
    blank_state = binary_executor.create_blank_state(binary_path)
    # Create and run an init state
    # TODO Something very fishy in here, why do we need to reverse the arg? angr's endianness handling keeps puzzling me
    init_state = binary_executor.create_calling_state(blank_state, "nf_init", [devices_count.reversed], libnf_init_externals)
    init_state.solver.add(devices_count.UGT(0))
    statistics.work_start("symbex")
    # ignore the graph of states here, it's just init
    result_states, _ = binary_executor.run_state(init_state)
    statistics.work_end()
    # Create handle states from all successful inits
    inited_states = []
    for state in result_states:
        # code to get the return value copied from angr's "Callable" implementation
        cc = angr.DEFAULT_CC[state.project.arch.name](state.project.arch)
        init_result = cc.get_return_val(state, stack_base=state.regs.sp - cc.STACKARG_SP_DIFF)
        state.solver.add(init_result != 0)
        if state.solver.satisfiable():
            state.path.clear() # less noise when debugging
            state_creator = lambda st: binary_executor.create_calling_state(st, "nf_handle", [klint.externals.net.packet.alloc(st, devices_count)], libnf_handle_externals)
            inited_states.append((state, state_creator))
    return inited_states

def execute_libnf(binary_path):
    print("libNF symbex starting at", datetime.datetime.now())
    devices_count = claripy.BVS('devices_count', 16) # TODO avoid the hardcoded 16 here
    inited_states = get_libnf_inited_states(binary_path, devices_count)
    result_states, result_graphs = find_fixedpoint_states(inited_states)
    print("libNF symbex done at", datetime.datetime.now())
    return (result_states, devices_count, result_graphs) # TODO devices_count should be in metadata somewhere, not explicitly returned


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
    init_state = binary_executor.create_calling_state(blank_state, "_start", [], nf_init_externals)
    global nf_inited_states
    assert nf_inited_states is not None
    nf_inited_states = []
    statistics.work_start("symbex")
    binary_executor.run_state(init_state, allow_trap=True) # this will fill nf_inited_states; we allow traps only here since that's how init can fail
    statistics.work_end()
    assert len(nf_inited_states) > 0
    result_states, _ = find_fixedpoint_states(nf_inited_states)
    print("NF symbex done at", datetime.datetime.now())
    return (result_states, claripy.BVV(2, 16)) # TODO ouch hardcoding, same remark as in execute_libnf
