# Standard/External libraries
import os
import unittest
import angr
import claripy

# Us
from binary.metadata import Metadata
from binary.memory_split import SplitMemory
from binary.ghost_maps import GhostMaps

# Disable logs we don't care about
import logging
logging.getLogger('cle.loader').setLevel('ERROR')
logging.getLogger('cle.backends.externs').setLevel('ERROR')
logging.getLogger('angr.engines.successors').setLevel('ERROR')
logging.getLogger('angr.project').setLevel('ERROR')

# Configure the plugins we need
angr.SimState.register_default("metadata", Metadata)
angr.SimState.register_default("sym_memory", SplitMemory) # SimState translates "sym_memory" to "memory" under standard options
angr.SimState.register_default("maps", GhostMaps)

# Can't find another way to create an empty state...
def empty_state():
    proj = angr.Project(os.path.dirname(os.path.realpath(__file__)) + "/empty_binary")
    return proj.factory.blank_state()

class Tests(unittest.TestCase):
    def test_set_then_get(self):
        state = empty_state()
    
        map = state.maps.new(8, 16)
    
        k = claripy.BVS("K", 8)
        v = claripy.BVS("V", 16)
    
        state.maps.set(map, k, v)
        self.assertEqual(state.maps.get(map, k), (v, claripy.true))

if __name__ == '__main__':
    unittest.main()