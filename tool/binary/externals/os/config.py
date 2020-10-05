# Standard/External libraries
import angr
import claripy
from collections import namedtuple

# Us
from ... import cast
from ... import utils
from ...exceptions import SymbexException

ConfigMetadata = namedtuple('ConfigMetadata', ['items'])

class ConfigU(angr.SimProcedure):
  def size(self):
    return 8

  def run(self, name):
    name = cast.ptr(name)

    if name.symbolic:
      raise SymbexException("Cannot use symbolic names for config")

    py_name = utils.read_str(self.state, name)

    metadata = self.state.metadata.get(ConfigMetadata, None, default=ConfigMetadata({}))

    if py_name not in metadata.items:
      value = claripy.BVS(py_name, self.size())
      metadata.items[py_name] = value

    value = metadata.items[py_name]

    return value

class ConfigU16(ConfigU):
  def size(self): return 16

class ConfigU32(ConfigU):
  def size(self): return 32

class ConfigU64(ConfigU):
  def size(self): return 64

class ConfigTime(ConfigU):
  def size(self): return 64

class ConfigDeviceMacs(ConfigU):
  def size(self): return 64
