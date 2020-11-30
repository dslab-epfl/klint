# Standard/External libraries
import angr
import claripy
from datetime import datetime
import subprocess
import traceback
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
from . import defs

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
  original_metadata_items = state.metadata.items_copy()
  config_items = state.metadata.get(config.ConfigMetadata, None, default=config.ConfigMetadata({})).items
  sm = bin_exec.create_sim_manager(bin_path, handle_externals, "nf_handle", *args, base_state=state)
  sm.run()
  if len(sm.errored) > 0:
    sm.errored[0].reraise()
  for ended in sm.deadended:
    state_input = defs.NFInput(
      packet = defs.ReceivedPacket(
        device = network.packet_get_device(state, packet),
        data = network.packet_get_data(state, packet),
        length = network.packet_get_length(state, packet)
      ),
      state_metadata = original_metadata_items,
      config = config_items
    )
    state_output = defs.NFOutput(
      packets = [
        defs.SentPacket(
          device = device,
          data = data,
          length = length,
          updated_ethernet_addresses = l2,
          updated_ip_checksum = l3,
          updated_udptcp_checksum = l4
        )
        for (data, length, device, l2, l3, l4) in ended.metadata.get(network.NetworkMetadata, None, default=network.NetworkMetadata([])).transmitted
      ],
      state = ended.copy()
    )

#    print("IN", state_input, "OUT", state_output, "CONSTRAINTS", ended.solver.constraints)
#    print("--------")
    yield (ended, state_input, state_output)

def havoc_iter(bin_path, state, devices_count):
    print("Running an iteration of handle, at " + str(datetime.now()) + "\n")
    original_state = state.copy()
    handled_states = list(nf_handle(bin_path, state, devices_count))
    for (s, _, _) in handled_states:
      print("State", id(s), "has", len(s.solver.constraints), "constraints")
      s.path.print()
      s.path.ghost_print()

    print("Merging... at " + str(datetime.now()))
    other_states = [s for (s, _, _) in handled_states[1:]]
    opaque_metadata_value = handled_states[0][0].metadata.notify_impending_merge(other_states, original_state)
    (new_state, _, merged) = handled_states[0][0].merge(*other_states, common_ancestor=original_state)
    if not merged:
      raise SymbexException("Not merged...")
    reached_fixpoint = new_state.metadata.notify_completed_merge(opaque_metadata_value)
    if reached_fixpoint:
        return (new_state, True)

    print("")
    return (new_state, False)


def execute(bin_path):
  devices_count = claripy.BVS('devices_count', 16)
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
      (state, reached_fixpoint) = havoc_iter(bin_path, state, devices_count)
    print("Done! at " + str(datetime.now()))
    return None
