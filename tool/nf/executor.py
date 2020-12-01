# Standard/External libraries
import angr
import claripy
from datetime import datetime
import subprocess
import os

# Us
import binary.executor as bin_exec
import binary.utils as utils
from binary.ghost_maps import GhostMaps
from binary.externals.os import clock
from binary.externals.os import config
from binary.externals.os import debug
from binary.externals.os import memory
from binary.externals.os import network
from binary.externals.os.structs import map
from binary.externals.os.structs import map2
from binary.externals.os.structs import pool
from binary.externals.os.structs import cht
from binary.externals.os.structs import lpm
from binary.exceptions import SymbexException

init_externals = {
    'os_config_get_u16': config.ConfigU16,
    'os_config_get_u32': config.ConfigU32,
    'os_config_get_u64': config.ConfigU64,
    'os_config_get_time': config.ConfigTime,
    'os_memory_alloc': memory.OsMemoryAlloc,
    'os_map_alloc': map.OsMapAlloc,
    'os_map2_alloc': map2.OsMap2Alloc,
    'os_pool_alloc': pool.OsPoolAlloc,
    'cht_alloc': cht.ChtAlloc,
    'lpm_alloc': lpm.LpmAlloc,
    'lpm_update_elem': lpm.LpmUpdateElem,
    # unfortunately needed to mimic BPF userspace
    'os_map2_havoc': map2.OsMap2Havoc,
    'os_memory_havoc': memory.OsMemoryHavoc,
}

handle_externals = {
    'os_clock_time': clock.Time,
    'os_debug': debug.Debug,
    'os_net_transmit': network.Transmit,
    'os_net_flood': network.Flood,
    'os_map_get': map.OsMapGet,
    'os_map_set': map.OsMapSet,
    'os_map_remove': map.OsMapRemove,
    'os_map2_get': map2.OsMap2Get,
    'os_map2_set': map2.OsMap2Set,
    'os_map2_remove': map2.OsMap2Remove,
    'os_pool_borrow': pool.OsPoolBorrow,
    'os_pool_return': pool.OsPoolReturn,
    'os_pool_refresh': pool.OsPoolRefresh,
    'os_pool_used': pool.OsPoolUsed,
    'os_pool_expire': pool.OsPoolExpire,
    'cht_find_preferred_available_backend': cht.ChtFindPreferredAvailableBackend,
    'lpm_lookup_elem': lpm.LpmLookupElem
}

def nf_init(bin_path, devices_count):
    # subprocess.check_call(["make", "-f" "../Makefile.nf"], cwd=nf_folder)
    args = [devices_count]
    sm = bin_exec.create_sim_manager(bin_path, init_externals, "nf_init", *args)
    sm.run()
    if len(sm.errored) > 0:
        sm.errored[0].reraise()
    return sm.deadended

def nf_handle(bin_path, state, devices_count):
    packet = network.packet_init(state, devices_count)
    args = [packet]
    sm = bin_exec.create_sim_manager(bin_path, handle_externals, "nf_handle", *args, base_state=state)
    sm.run()
    if len(sm.errored) > 0:
        sm.errored[0].reraise()
    return sm.deadended

def havoc_iter(bin_path, state, devices_count):
    print("Running an iteration of handle, at " + str(datetime.now()) + "\n")
    original_state = state.copy()
    handled_states = list(nf_handle(bin_path, state, devices_count))
    handled_states_copy = [s.copy() for s in handled_states]
    for s in handled_states:
        print("State", id(s), "has", len(s.solver.constraints), "constraints")
        s.path.print()
        #s.path.ghost_print()

    print("Merging... at " + str(datetime.now()))
    opaque_metadata_value = handled_states[0].metadata.notify_impending_merge(handled_states[1:], original_state)
    (new_state, _, merged) = handled_states[0].merge(*handled_states[1:], common_ancestor=original_state)
    if not merged:
        raise SymbexException("Not merged...")
    reached_fixpoint = new_state.metadata.notify_completed_merge(opaque_metadata_value)

    print("")
    return (handled_states, new_state, reached_fixpoint)


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
        while not reached_fixpoint:
            (handled_states, state, reached_fixpoint) = havoc_iter(bin_path, state, devices_count)
            if reached_fixpoint:
                results += handled_states
    print("NF symbex done! at", datetime.now())
    return (results, devices_count)
