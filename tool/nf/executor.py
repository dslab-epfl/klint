# Standard/External libraries
import angr
import claripy
from datetime import datetime
import subprocess
import os

# Us
import binary.executor as bin_exec
import binary.utils as utils
import binary.ghost_maps as ghost_maps
from binary.externals.os import clock
from binary.externals.os import config
from binary.externals.os import error
from binary.externals.os import memory
from binary.externals.os import pci
from binary.externals.compat import memcpy
from binary.externals.net import packet
from binary.externals.net import tx
from binary.externals.structs import map
from binary.externals.structs import map2
from binary.externals.structs import index_pool
from binary.externals.structs import cht
from binary.externals.structs import lpm
from binary.externals.verif import functions
from binary.exceptions import SymbexException
from . import spec_act
from . import spec_reg

# TODO: all these externals should be in nf... not in binary... !

init_externals = {
    'os_config_get': config.os_config_get,
    'os_memory_alloc': memory.os_memory_alloc,
    'map_alloc': map.map_alloc,
    'os_map2_alloc': map2.OsMap2Alloc,
    'index_pool_alloc': index_pool.index_pool_alloc,
    'os_halt': error.os_halt,
    'cht_alloc': cht.ChtAlloc,
    'lpm_alloc': lpm.LpmAlloc,
    'lpm_update_elem': lpm.LpmUpdateElem,
    # unfortunately needed to mimic BPF userspace
    'os_map2_havoc': map2.OsMap2Havoc,
    'os_memory_havoc': memory.os_memory_havoc
}

handle_externals = {
    'os_clock_time_ns': clock.os_clock_time_ns,
    'os_debug': error.os_debug,
    'net_transmit': tx.net_transmit,
    'net_flood': tx.net_flood,
    'map_get': map.map_get,
    'map_set': map.map_set,
    'map_remove': map.map_remove,
    'os_map2_get': map2.OsMap2Get,
    'os_map2_set': map2.OsMap2Set,
    'os_map2_remove': map2.OsMap2Remove,
    'index_pool_borrow': index_pool.index_pool_borrow,
    'index_pool_return': index_pool.index_pool_return,
    'index_pool_refresh': index_pool.index_pool_refresh,
    'index_pool_used': index_pool.index_pool_used,
    'cht_find_preferred_available_backend': cht.ChtFindPreferredAvailableBackend,
    'lpm_lookup_elem': lpm.LpmLookupElem,
    # whyyy
    'memcpy': memcpy.Memcpy
}

total_externals = {
    'os_clock_time_ns': clock.os_clock_time_ns,
    'os_clock_sleep_ns': clock.os_clock_sleep_ns,
    'os_config_get': config.os_config_get,
    'os_halt': error.os_halt,
    'os_memory_alloc': memory.os_memory_alloc,
    'os_memory_phys_to_virt': memory.os_memory_phys_to_virt,
    'os_memory_virt_to_phys': memory.os_memory_virt_to_phys,
    'os_pci_enumerate': pci.os_pci_enumerate,
    'os_pci_read': pci.os_pci_read,
    'os_pci_write': pci.os_pci_write,
    'foreach_index': functions.foreach_index
}

def nf_init(bin_path, devices_count):
    # subprocess.check_call(["make", "-f" "../Makefile.nf"], cwd=nf_folder)
    args = [devices_count]
    sm = bin_exec.create_sim_manager(bin_path, init_externals, "nf_init", *args)
    sm.active[0].add_constraints(devices_count.UGT(0))
    sm.run()
    if len(sm.errored) > 0:
        sm.errored[0].reraise()
    return sm.deadended

def nf_handle(bin_path, state, devices_count):
    pkt = packet.alloc(state, devices_count)
    args = [pkt]
    sm = bin_exec.create_sim_manager(bin_path, handle_externals, "nf_handle", *args, base_state=state)
    sm.run()
    if len(sm.errored) > 0:
        sm.errored[0].reraise()
    return sm.deadended

def havoc_iter(bin_path, state, devices_count, previous_results):
    print("Running an iteration of handle, at", datetime.now(), "\n")
    original_state = state.copy()
    handled_states = list(nf_handle(bin_path, state, devices_count))
    for s in handled_states:
        print("State", id(s), "has", len(s.solver.constraints), "constraints")
        s.path.print()
        #s.path.ghost_print()

    print("Inferring invariants... at ", datetime.now())
    (new_state, new_results, reached_fixpoint) = ghost_maps.infer_invariants(original_state, handled_states, previous_results)

    print("")
    return (handled_states, new_state, new_results, reached_fixpoint)


def execute(bin_path):
    devices_count = claripy.BVS('devices_count', 16)
    results = []
    for state in nf_init(bin_path, devices_count):
        # code to get the return value copied from angr's "Callable" implementation
        cc = angr.DEFAULT_CC[state.project.arch.name](state.project.arch)
        init_result = cc.get_return_val(state, stack_base=state.regs.sp - cc.STACKARG_SP_DIFF)
        try:
            utils.add_constraints_and_check_sat(state, init_result != 0)
        except angr.errors.SimUnsatError:
            continue
        reached_fixpoint = False
        previous_results = None
        while not reached_fixpoint:
            (handled_states, state, previous_results, reached_fixpoint) = havoc_iter(bin_path, state, devices_count, previous_results)
            if reached_fixpoint:
                results += handled_states
    print("NF symbex done! at", datetime.now())
    return (results, devices_count)

def execute_full(bin_path):
    spec_reg.validate_registers(spec_reg.registers)
    spec_reg.validate_registers(spec_reg.pci_regs)
    spec_act.validate_actions()
    #spec_glo.validate_globals()
    sm = bin_exec.create_sim_manager(bin_path, total_externals, "main", [0, 0]) # args = argc, argv
    sm.run()
    if len(sm.errored) > 0:
        sm.errored[0].reraise()