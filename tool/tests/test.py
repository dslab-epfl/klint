import angr
import claripy
import os
import unittest

from binary.ghost_maps import Map
from binary.sizes import SizesPlugin

# Disable logs we don't care about
import logging
logging.getLogger('cle.loader').setLevel('ERROR')
logging.getLogger('cle.backends.externs').setLevel('ERROR')
logging.getLogger('angr.engines.successors').setLevel('ERROR')
logging.getLogger('angr.project').setLevel('ERROR')

angr.SimState.register_default("sizes", SizesPlugin)

# Can't find another way to create an empty state...
def empty_state():
    proj = angr.Project(os.path.dirname(os.path.realpath(__file__)) + "/empty_binary")
    return proj.factory.blank_state()

k = claripy.BVS("K", 8)
k2 = claripy.BVS("K2", 8)
v = claripy.BVS("V", 16)

class Tests(unittest.TestCase):
    def assertSolver(self, state, cond):
        self.assertEqual(state.solver.eval_one(cond), True)

    def test_get_after_set(self):
        state = empty_state()
        map = Map.new(state, 8, 16, "test")
        map = map.set(state, k, v)
        result = map.get(state, k)
        self.assertSolver(state, result[1])
        self.assertSolver(state, result[0] == v)

    def test_get_when_empty(self):
        state = empty_state()
        map = Map.new(state, 8, 16, "test")
        self.assertSolver(state, map.get(state, k)[1] == claripy.false)

    def test_get_after_set_and_remove(self):
        state = empty_state()
        map = Map.new(state, 8, 16, "test")
        map = map.set(state, k, v)
        map = map.remove(state, k)
        self.assertSolver(state, map.get(state, k)[1] == claripy.false)

    def test_get_time_travels(self):
        state = empty_state()
        state.solver.add(k != k2)
        map = Map.new_array(state, 8, 16, 10, "test")
        map2 = map.set(state, k, v)
        state.solver.add(map2.get(state, k2)[1])
        self.assertSolver(state, map.get(state, k2)[1])

if __name__ == '__main__':
    unittest.main()