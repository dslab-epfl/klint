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

K = claripy.BVS("K", 8)
K2 = claripy.BVS("K2", 8)
V = claripy.BVS("V", 16)
X = claripy.BVS("X", 16)
Y = claripy.BVS("Y", 16)

class Tests(unittest.TestCase):
    def assertSolver(self, state, cond):
        self.assertEqual(state.solver.eval_one(cond), True)

    def test_get_after_set(self):
        state = empty_state()
        map = Map.new(state, 8, 16, "test")
        map = map.set(state, K, V)
        result = map.get(state, K)
        self.assertSolver(state, result[1])
        self.assertSolver(state, result[0] == V)

    def test_get_when_empty(self):
        state = empty_state()
        map = Map.new(state, 8, 16, "test")
        self.assertSolver(state, map.get(state, K)[1] == claripy.false)

    def test_get_after_set_and_remove(self):
        state = empty_state()
        map = Map.new(state, 8, 16, "test")
        map = map.set(state, K, V)
        map = map.remove(state, K)
        self.assertSolver(state, map.get(state, K)[1] == claripy.false)

    def test_get_time_travels(self):
        state = empty_state()
        state.solver.add(K != K2)
        map = Map.new_array(state, 8, 16, 10, "test")
        map2 = map.set(state, K, V)
        state.solver.add(map2.get(state, K2)[1])
        self.assertSolver(state, map.get(state, K2)[1])

    def test_get_time_travels_2(self):
        state = empty_state()
        state.solver.add(K != K2)
        map = Map.new_array(state, 8, 16, 10, "test")
        map2 = map.set(state, K, V)
        state.solver.add(map.get(state, K2)[1])
        self.assertSolver(state, map2.get(state, K2)[1])

    def test_forall(self):
        state = empty_state()
        map = Map.new_array(state, 8, 16, 10, "test")
        state.solver.add(map.forall(state, lambda k, v: v == 42))
        result = map.get(state, K)
        self.assertSolver(state, ~result[1] | (result[0] == 42))

    def test_forall_implies(self):
        state = empty_state()
        map = Map.new_array(state, 8, 16, 10, "test")
        ge_x = map.forall(state, lambda k, v: v >= X)
        ge_y = map.forall(state, lambda k, v: v >= Y)
        self.assertSolver(state, ~(ge_x & (X >= Y)) | ge_y)

    def test_forall_time_travels(self):
        state = empty_state()
        map = Map.new_array(state, 8, 16, 10, "test")
        map2 = map.set(state, K, 42)
        state.solver.add(map2.forall(state, lambda k, v: v == 42))
        self.assertSolver(state, map.forall(state, lambda k, v: v == 42))

    def test_forall_time_travels_2(self):
        state = empty_state()
        map = Map.new_array(state, 8, 16, 10, "test")
        map2 = map.set(state, K, 42)
        state.solver.add(map.forall(state, lambda k, v: v == 42))
        self.assertSolver(state, map2.forall(state, lambda k, v: v == 42))


if __name__ == '__main__':
    unittest.main()
