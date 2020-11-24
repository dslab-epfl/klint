#!/usr/bin/env python

# TODO this file is completely obsolete, I think? but it serves as a convenient way to run verification (see the end), so whatever
# TODO would be cleaner to unwrap everything during symbex... but recursively unwrapping stuff gets hairy

# Standard/External libraries
import claripy
import sys
import os
import pathlib

# Us
import nf.defs as defs
import nf.executor as nf_executor
import python.executor as py_executor
import python.symbex as py_symbex

# TODO proper argument/state checking
def spec_send(state, packet, device, **kwargs):
  if 'packets' not in state: state['packets'] = []
  state['packets'].append(defs.SentPacket(
    device = device,
    data = packet.data,
    length = packet.length,
    updated_ethernet_addresses = kwargs.get('update_ethernet_addrs', False),
    updated_ip_checksum = kwargs.get('update_ip_checksum', False),
    updated_udptcp_checksum = kwargs.get('update_udptcp_checksum', False)
  ))
def spec_end(state):
  state['total'] = True

def to_claripy(val):
  if isinstance(val, py_symbex.ValueProxy):
    return to_claripy(val.wrapped)
  if isinstance(val, claripy.ast.base.Base):
    return val
  if isinstance(val, bool):
    return claripy.BVV(1 if val else 0, 64)
  print(type(val))
  raise NotImplementedError()

def check_one(solver, spec_out, code_out):
  if not code_out.total:
    raise NotImplementedError() # not sure if we ever want to allow this; what would it mean?

  if not spec_out.total:
    raise NotImplementedError() # TODO

  if len(spec_out.packets) != len(code_out.packets):
    raise AssertionError("Total outputs do not have the same number of packets")

  constraint = claripy.true
  for (sp, cp) in zip(spec_out.packets, code_out.packets):
    sd = sp._asdict()
    cd = cp._asdict()
    for key in sd.keys():
      constraint &= to_claripy(sd[key]) == cd[key]

  if solver.eval_upto(constraint, 3) != [True]:
    raise AssertionError("Not necessarily true: " + str(constraint))

def check(nf_folder):
  with open(nf_folder + os.sep + 'spec.py') as spec_file:
    _ = spec_file.read()

  # spec_externals = {
  #   'send': spec_send,
  #   'end': spec_end
  # }

  nf_executor.execute(nf_folder)
  print("OK")
  #for (state_solver, state_input, state_output) in nf_results:
    # note: _asdict is named that way to avoid name clashes, we're not using a private method here
  #  py_results = py_executor.execute(state_solver, spec_text, state_input._asdict().values(), spec_externals)
  #  for (spec_pathcond, spec_output) in py_results:
      # ignore spec_pathcond, the outputs must match regardless of the spec structure
  #    check_one(state_solver, defs.NFOutput(**spec_output), state_output)

nf_to_verify = "hxdp-new"
if len(sys.argv) == 2:
  nf_to_verify = sys.argv[1]
check(f"{pathlib.Path(__file__).parent.absolute()}{os.sep + '..' + os.sep}nf{os.sep + nf_to_verify}")
