from angr.state_plugins.sim_action import SimActionObject
import executors.binary.bitsizes as bitsizes

# TODO remove anything unneeded (ideally we should have no variable-width types like int, unsigned, ...)

def _fix(o):
  if isinstance(o, SimActionObject):
    o = o.ast
  return o

def u64(o):
  return _fix(o)

def u32(o):
  return _fix(o)[31:0]

def u16(o):
  return _fix(o)[15:0]

def i64(o):
  return _fix(o)

def int(o):
  return _fix(o)[(bitsizes.INT-1):0]

def unsigned(o):
  return _fix(o)[(bitsizes.INT-1):0]

def ptr(o):
  return _fix(o)
