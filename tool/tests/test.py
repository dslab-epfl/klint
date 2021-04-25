import angr
import claripy
import os
import unittest

from binary.executor import CustomSolver
from binary.ghost_maps import Map, GhostMapsPlugin, MapGet, MapHas
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
    proj = angr.Project(os.path.dirname(os.path.realpath(__file__)) + "/empty_binary", simos=angr.simos.SimOS)
    state = proj.factory.blank_state()
    state.solver._stored_solver = CustomSolver()
    state.maps = GhostMapsPlugin()
    state.maps.set_state(state)
    return state

KEY_SIZE = 8
VALUE_SIZE = 16

B = claripy.BoolS("B")
K = claripy.BVS("K", KEY_SIZE)
K2 = claripy.BVS("K2", KEY_SIZE)
V = claripy.BVS("V", VALUE_SIZE)
X = claripy.BVS("X", VALUE_SIZE)
Y = claripy.BVS("Y", VALUE_SIZE)

# TODO add "forking" tests, i.e. M1 -> M2 and M1 -> M3 then assert stuff on M2 and M3

# TODO fix the naming of these tests...

# TODO this is a good way to prototype a better API for the ghost maps in code...

class Tests(unittest.TestCase):
    def assertSolver(self, state, cond):
        result = state.solver.eval_upto(cond, 2)
        if result == [True]:
            return # Good!
        if result == [False]:
            raise Exception("UNSOUND! VERY BAD! FIX ASAP!!!!!")
        raise AssertionError("Incomplete, but sound")

    def assertSolverUnknown(self, state, cond):
        result = state.solver.eval_upto(cond, 2)
        if len(result) == 1:
            raise Exception("UNSOUND! VERY BAD! FIX ASAP!!!!!")
        # OK


    def test_get_after_set(self):
        state = empty_state()
        map = Map.new(state, KEY_SIZE, VALUE_SIZE, "test")
        map = map.set(state, K, V)
        result = map.get(state, K)
        self.assertSolver(state, result[1])
        self.assertSolver(state, result[0] == V)

    def test_get_when_empty(self):
        state = empty_state()
        map = Map.new(state, KEY_SIZE, VALUE_SIZE, "test")
        self.assertSolver(state, map.get(state, K)[1] == claripy.false)

    def test_get_after_set_and_remove(self):
        state = empty_state()
        map = Map.new(state, KEY_SIZE, VALUE_SIZE, "test")
        map = map.set(state, K, V)
        map = map.remove(state, K)
        self.assertSolver(state, map.get(state, K)[1] == claripy.false)

    def test_get_time_travels(self):
        state = empty_state()
        state.solver.add(K != K2)
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        map2 = map.set(state, K, V)
        state.solver.add(map2.get(state, K2)[1])
        self.assertSolver(state, map.get(state, K2)[1])

    def test_get_time_travels_2(self):
        state = empty_state()
        state.solver.add(K != K2)
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        map2 = map.set(state, K, V)
        state.solver.add(map.get(state, K2)[1])
        self.assertSolver(state, map2.get(state, K2)[1])

    def test_get_unknown(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        self.assertSolverUnknown(state, map.get(state, K)[1])

    def test_get_different_values_imply_different_keys(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        (v1, p1) = map.get(state, K)
        (v2, p2) = map.get(state, K2)
        self.assertSolver(state, ~((p1 & p2) & (v1 != v2)) | (K != K2))

    def test_forall(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        state.solver.add(map.forall(state, lambda k, v: v == 42))
        result = map.get(state, K)
        self.assertSolver(state, ~result[1] | (result[0] == 42))

    def test_forall_lone_specific_key(self):
        state = empty_state()
        map = Map.new(state, KEY_SIZE, VALUE_SIZE, "test", _length=1, _invariants=[lambda i: claripy.true])
        state.solver.add(map.forall(state, lambda k, v: k == 42))
        result = map.get(state, K)
        self.assertSolver(state, ~result[1] | (K == 42))

    def test_forall_2(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        result = map.get(state, K)
        state.solver.add(map.forall(state, lambda k, v: v == 42))
        self.assertSolver(state, ~result[1] | (result[0] == 42))

    def test_forall_3(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        state.solver.add(map.forall(state, lambda k, v: v == 42))
        self.assertSolver(state, map.forall(state, lambda k, v: v >= 42))

    def test_forall_4(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 0, "test")
        map2 = map.set(state, K, V)
        self.assertSolver(state, ~map2.forall(state, lambda k, v: v != V))

    def test_forall_all_known(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 1, "test")
        state.solver.add(map.forall(state, lambda k, v: v == 0))
        map2 = map.set(state, claripy.BVV(0, KEY_SIZE), claripy.BVV(42, VALUE_SIZE))
        self.assertSolver(state, map2.forall(state, lambda k, v: v == 42))

    def test_forall_false(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        map = map.set(state, K, claripy.BVV(0, VALUE_SIZE))
        self.assertSolver(state, ~map.forall(state, lambda k, v: v == 42))

    def test_forall_false_2(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        state.solver.add(map.forall(state, lambda k, v: v == 0))
        map2 = map.set(state, K, claripy.BVV(42, VALUE_SIZE))
        self.assertSolver(state, ~map2.forall(state, lambda k, v: v == 0))

    def test_forall_unknown(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        self.assertSolverUnknown(state, map.forall(state, lambda k, v: v == 42))

    def test_forall_unknown_2(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        result = map.get(state, K)
        forall_result = map.forall(state, lambda k, v: v == 42)
        state.solver.add(result[1] & (result[0] == 0))
        result2 = map.get(state, K2)
        state.solver.add(result2[1])
        self.assertSolverUnknown(state, result2[0] == 42)

    def test_forall_implies(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        ge_x = map.forall(state, lambda k, v: v >= X)
        ge_y = map.forall(state, lambda k, v: v >= Y)
        self.assertSolver(state, ~(ge_x & (X >= Y)) | ge_y)

    def test_forall_implies_2(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        ge_x = map.forall(state, lambda k, v: v >= X)
        ge_y = map.forall(state, lambda k, v: v >= Y)
        self.assertSolver(state, ~(ge_y & (Y >= X)) | ge_x)

    def test_forall_implies_not(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        lt_x = map.forall(state, lambda k, v: v < X)
        gt_y = map.forall(state, lambda k, v: v > Y)
        self.assertSolver(state, ~(lt_x & (X < Y)) | ~gt_y)

    def test_forall_implies_not_2(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        lt_x = map.forall(state, lambda k, v: v < X)
        gt_y = map.forall(state, lambda k, v: v > Y)
        self.assertSolver(state, ~(gt_y & (Y > X)) | ~lt_x)

    def test_forall_time_travels_future_true(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        map2 = map.set(state, claripy.BVV(500, KEY_SIZE), claripy.BVV(42, VALUE_SIZE)) # wasn't there
        state.solver.add(map2.forall(state, lambda k, v: v == 42))
        self.assertSolver(state, map.forall(state, lambda k, v: v == 42))

    def test_forall_time_travels_future_false(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        map2 = map.set(state, K, claripy.BVV(42, VALUE_SIZE))
        state.solver.add(~map2.forall(state, lambda k, v: v == 42))
        self.assertSolver(state, ~map.forall(state, lambda k, v: v == 42))

    def test_forall_time_travels_future_unknown(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        map2 = map.remove(state, K)
        state.solver.add(map2.forall(state, lambda k, v: v == 42))
        self.assertSolverUnknown(state, map.forall(state, lambda k, v: v == 42))

    def test_forall_time_travels_past_true(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        map2 = map.set(state, K, 42)
        state.solver.add(map.forall(state, lambda k, v: v == 42))
        self.assertSolver(state, map2.forall(state, lambda k, v: v == 42))

    def test_forall_time_travels_past_false(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        map2 = map.set(state, claripy.BVV(500, KEY_SIZE), claripy.BVV(42, VALUE_SIZE)) # wasn't there!
        state.solver.add(~map.forall(state, lambda k, v: v == 42))
        self.assertSolver(state, ~map2.forall(state, lambda k, v: v == 42))

    def test_forall_time_travels_past_unknown(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        map2 = map.set(state, K, claripy.BVV(42, VALUE_SIZE))
        state.solver.add(~map.forall(state, lambda k, v: v == 42))
        self.assertSolverUnknown(state, ~map2.forall(state, lambda k, v: v == 42))

    def test_forall_existing_invariant(self):
        state = empty_state()
        map = Map.new(state, KEY_SIZE, VALUE_SIZE, "test", _length=10, _invariants=[lambda i: ~i.present | (i.value == 42)])
        self.assertSolver(state, map.forall(state, lambda k, v: v >= 42))

    def test_forall_impossible_invariant(self):
        state = empty_state()
        map1 = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test1")
        map2 = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 100, "test2")
        self.assertSolver(state, ~map2.forall(state, lambda k, v: map1.get(state, k)[1]))

    def test_forall_split(self):
        state = empty_state()
        map = Map.new_array(state, KEY_SIZE, VALUE_SIZE, 10, "test")
        state.solver.add(map.forall(state, lambda k, v: v == X))
        map2 = map.set(state, claripy.BVV(0, KEY_SIZE), Y)
        self.assertSolver(state, map2.forall(state, lambda k, v: v == claripy.If(k == 0, Y, X)))

    def test_forall_cross_o1first(self):
        state = empty_state()
        o1 = claripy.BVS("O", 64)
        o2 = claripy.BVS("O", 64)
        state.maps[o1] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test1", _length=10, _invariants=[lambda i: claripy.true])
        state.maps[o2] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test2", _length=10, _invariants=[lambda i: claripy.true])
        state.solver.add(state.maps.forall(o2, lambda k, v: v < X))
        state.solver.add(state.maps.forall(o1, lambda k, v: MapHas(o2, k, v)))
        state.solver.add(state.maps.forall(o2, lambda k, v: MapHas(o1, k, v))) # this seemingly-pointless line could cause a failure
        self.assertSolver(state, state.maps.forall(o1, lambda k, v: v < X))

    def test_forall_cross_o1first_reversed(self):
        state = empty_state()
        o1 = claripy.BVS("O", 64)
        o2 = claripy.BVS("O", 64)
        state.maps[o1] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test1", _length=10, _invariants=[lambda i: claripy.true])
        state.maps[o2] = Map.new(state, VALUE_SIZE, KEY_SIZE, "test2", _length=10, _invariants=[lambda i: claripy.true])
        state.solver.add(state.maps.forall(o2, lambda k, v: k < X))
        state.solver.add(state.maps.forall(o1, lambda k, v: MapHas(o2, v, k)))
        state.solver.add(state.maps.forall(o2, lambda k, v: MapHas(o1, v, k))) # this seemingly-pointless line could cause a failure
        self.assertSolver(state, state.maps.forall(o1, lambda k, v: v < X))

    def test_forall_cross_o2first(self):
        state = empty_state()
        o1 = claripy.BVS("O", 64)
        o2 = claripy.BVS("O", 64)
        state.maps[o1] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test1", _length=10, _invariants=[lambda i: claripy.true])
        state.maps[o2] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test2", _length=10, _invariants=[lambda i: claripy.true])
        state.solver.add(state.maps.forall(o2, lambda k, v: v < X))
        state.solver.add(state.maps.forall(o2, lambda k, v: MapHas(o1, k, v))) # this seemingly-pointless line could cause a failure
        state.solver.add(state.maps.forall(o1, lambda k, v: MapHas(o2, k, v)))
        self.assertSolver(state, state.maps.forall(o1, lambda k, v: v < X))

    def test_forall_cross_o2first_reversed(self):
        state = empty_state()
        o1 = claripy.BVS("O", 64)
        o2 = claripy.BVS("O", 64)
        state.maps[o1] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test1", _length=10, _invariants=[lambda i: claripy.true])
        state.maps[o2] = Map.new(state, VALUE_SIZE, KEY_SIZE, "test2", _length=10, _invariants=[lambda i: claripy.true])
        state.solver.add(state.maps.forall(o2, lambda k, v: k < X))
        state.solver.add(state.maps.forall(o2, lambda k, v: MapHas(o1, v, k))) # this seemingly-pointless line could cause a failure
        state.solver.add(state.maps.forall(o1, lambda k, v: MapHas(o2, v, k)))
        self.assertSolver(state, state.maps.forall(o1, lambda k, v: v < X))

    def test_forall_cross_o2first_weird(self):
        state = empty_state()
        o1 = claripy.BVS("O", 64)
        o2 = claripy.BVS("O", 64)
        state.maps[o1] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test1", _length=10, _invariants=[lambda i: claripy.true])
        state.maps[o2] = Map.new(state, VALUE_SIZE, KEY_SIZE, "test2", _length=10, _invariants=[lambda i: claripy.true])
        state.solver.add(state.maps.forall(o2, lambda k, v: k < X))
        state.solver.add(state.maps.forall(o2, lambda k, v: MapHas(o1, v + 1, k))) # this seemingly-pointless line could cause a failure
        state.solver.add(state.maps.forall(o1, lambda k, v: MapHas(o2, v, k - 1)))
        self.assertSolver(state, state.maps.forall(o1, lambda k, v: v < X))

    def test_forall_cross_o2first_weird2(self):
        state = empty_state()
        o1 = claripy.BVS("O", 64)
        o2 = claripy.BVS("O", 64)
        state.maps[o1] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test1", _length=10, _invariants=[lambda i: claripy.true])
        state.maps[o2] = Map.new(state, VALUE_SIZE, KEY_SIZE, "test2", _length=10, _invariants=[lambda i: claripy.true])
        state.solver.add(state.maps.forall(o2, lambda k, v: k < X))
        state.solver.add(state.maps.forall(o2, lambda k, v: MapHas(o1, v, k + 1))) # this seemingly-pointless line could cause a failure
        state.solver.add(state.maps.forall(o1, lambda k, v: MapHas(o2, v - 1, k)))
        self.assertSolver(state, state.maps.forall(o1, lambda k, v: v - 1 < X))

    def test_forall_implies_but_not_there(self):
        state = empty_state()
        o1 = claripy.BVS("O", 64)
        o2 = claripy.BVS("O", 64)
        state.maps[o1] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test1", _length=10, _invariants=[lambda i: claripy.true])
        state.maps[o2] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test2", _length=10, _invariants=[lambda i: claripy.true])
        state.solver.add(state.maps.forall(o1, lambda k, v: MapHas(o2, k, X)))
        (v1, p1) = state.maps.get(o1, K)
        state.solver.add(~p1)
        (v2, p2) = state.maps.get(o2, K)
        state.solver.add(p2)
        self.assertSolverUnknown(state, v2 == X)


if __name__ == '__main__':
    unittest.main()
