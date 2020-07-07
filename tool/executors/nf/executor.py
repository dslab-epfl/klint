# Python
import itertools
import subprocess
import traceback
import os
# Angr
import angr
import claripy
# Our executors (TODO: ideally, the externals shouldn't depend on a specific executor...)
import executors.binary.executor as bin_exec
from executors.binary.ghost_maps import GhostMaps
from executors.binary.externals.os import clock
from executors.binary.externals.os import config
from executors.binary.externals.os import debug
from executors.binary.externals.os import memory
from executors.binary.externals.os import network
from executors.binary.externals.os.structs import dchain
from executors.binary.externals.os.structs import map
# Us
import executors.nf.defs as defs

init_externals = {
  'os_config_get_u16': config.ConfigU16,
  'os_config_get_u32': config.ConfigU32,
  'os_config_get_u64': config.ConfigU64,
  'os_memory_init': memory.MemoryInit,
  'os_map_init': map.MapInit,
  'os_dchain_init': dchain.DChainInit
}

handle_externals = {
  'os_clock_time': clock.Time,
  'os_debug': debug.Debug,
  'os_net_transmit': network.Transmit,
  'os_net_flood': network.Flood,
  'os_map_get': map.MapGet,
  'os_map_put': map.MapPut,
  'os_map_erase': map.MapErase,
  'os_dchain_add': dchain.DChainAdd,
  'os_dchain_refresh': dchain.DChainRefresh,
  'os_dchain_expire': dchain.DChainExpire,
  'os_dchain_get': dchain.DChainGet,
#  'os_dchain_remove': dchain.DChainRemove
}

def nf_init(nf_folder, devices_count):
  # subprocess.check_call(["make", "-f" "../Makefile.nf"], cwd=nf_folder)
  args = [devices_count]
  sm = bin_exec.create_sim_manager(nf_folder + os.sep + "libnf.so", init_externals, "nf_init", *args)
  sm.run()
  if len(sm.errored) > 0:
    sm.errored[0].reraise()
  return sm.deadended

def nf_handle(nf_folder, state, devices_count):
  packet = network.packet_init(state, devices_count)
  args = [packet]
  original_metadata_items = state.metadata.items_copy()
  config_items = state.metadata.get(config.ConfigMetadata, None, default=config.ConfigMetadata({})).items
  sm = bin_exec.create_sim_manager(nf_folder + os.sep + "libnf.so", handle_externals, "nf_handle", *args, base_state=state)
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

def havoc_iter(nf_folder, state, devices_count):
    print("Running an iteration of handle...")
    print("")
    original_state = state.copy()
    handled_states = list(nf_handle(nf_folder, state, devices_count))
    for (s, i, o) in handled_states:
      print("=== STATE ===")
      print("Constraints:")
      print(s.solver.constraints)
      print("===       ===")
      print("")

    print("Merging...")
    other_states = [s for (s, i, o) in handled_states[1:]]
    opaque_metadata_value = handled_states[0][0].metadata.notify_impending_merge(other_states, original_state)
    (new_state, flag_comps, merged) = handled_states[0][0].merge(*other_states, common_ancestor=original_state)
    if not merged:
      raise "Not merged..."
    reached_fixpoint = new_state.metadata.notify_completed_merge(opaque_metadata_value)
    if reached_fixpoint:
        return (new_state, True)

    # remove a hopefully-pointless constraint
    pointless_constraint = [c for c in new_state.solver.constraints if next((c2 for c2 in c.children_asts() if c2.structurally_match(flag_comps[0])), None) is not None]
    if len(pointless_constraint) == 1:
      new_state.solver.constraints.pop(next(i for i in range(len(new_state.solver.constraints)) if new_state.solver.constraints[i].structurally_match(pointless_constraint[0])))
      new_state.solver.reload_solver()

    print("Merged constraints:")
    print(new_state.solver.constraints)
    print("")
    return (new_state, False)


def execute(nf_folder):
  devices_count = claripy.BVS('devices_count', 16)
  for state in nf_init(nf_folder, devices_count):
    state.solver.all_variables.append(devices_count) # since it's an arg, we have to add it explicitly... would be cleaner to create a blank state and start from that I guess?
    # code to get the return value copied from angr's "Callable" implementation
    cc = angr.DEFAULT_CC[state.project.arch.name](state.project.arch)
    init_result = state.solver.simplify(cc.get_return_val(state, stack_base=state.regs.sp - cc.STACKARG_SP_DIFF))
    state.add_constraints(init_result != 0)
    if not state.solver.satisfiable():
#      print("DISCARDING", state.solver.constraints)
      continue
    while True:
        (state, reached_fixpoint) = havoc_iter(nf_folder, state, devices_count)
        if reached_fixpoint:
            break
    raise "yay"
