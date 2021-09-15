import angr
import claripy
import copy
import os
import unittest

from kalm import executor as kalm_executor
from kalm.solver import KalmSolver
from kalm.plugins import SizesPlugin
from klint.ghostmaps import Map, GhostMapsPlugin, MapGet, MapHas

# Disable logs we don't care about
import logging
logging.getLogger('cle.loader').setLevel('ERROR')
logging.getLogger('cle.backends.externs').setLevel('ERROR')
logging.getLogger('angr.engines.successors').setLevel('ERROR')
logging.getLogger('angr.project').setLevel('ERROR')

angr.SimState.register_default("sizes", SizesPlugin)

# Can't find another way to create an empty state...
def empty_state():
    state = kalm_executor.create_blank_state(os.path.dirname(os.path.realpath(__file__)) + "/empty_binary")
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

    def test_forall_lone_specific_key_2(self):
        state = empty_state()
        map = Map.new(state, KEY_SIZE, VALUE_SIZE, "test")
        map2 = map.set(state, K, V)
        self.assertSolver(state, map2.forall(state, lambda k, v: v == V))

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

    # TODO why can't we prove this?
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

    def test_forall_itself(self):
        state = empty_state()
        map = Map.new(state, KEY_SIZE, VALUE_SIZE, "test", _length=10, _invariants=[lambda i: claripy.true])
        self.assertSolver(state, map.forall(state, lambda k, v: MapHas(map, k, value=v)))

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


    def test_forall_removed_value(self):
        state = empty_state()
        o1 = claripy.BVS("O1", 64)
        o2 = claripy.BVS("O2", 64)
        state.maps[o1] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test1", _length=10, _invariants=[lambda i: claripy.true])
        state.maps[o2] = Map.new(state, VALUE_SIZE, KEY_SIZE, "test2", _length=10, _invariants=[lambda i: claripy.true])
        state.solver.add(state.maps.forall(o1, lambda k, v: MapHas(o2, v, 1)))
        (v, p) = state.maps.get(o1, K)
        state.solver.add(p)
        state.maps.remove(o1, K)
        state.maps.set(o2, v, 0)
        self.assertSolver(state, state.maps.forall(o1, lambda k, v: MapHas(o2, v, 1)))


    def test_forall_subset(self):
        state = empty_state()
        o1 = claripy.BVS("O1", 64)
        state.maps[o1] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test1", _length=10, _invariants=[lambda i: claripy.true])
        (v, p) = state.maps.get(o1, K)
        o2 = claripy.BVS("O2", 64)
        state.maps[o2] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test2", _length=100, _invariants=[lambda i: claripy.true])
        state.solver.add(state.maps.forall(o1, lambda k, v: MapHas(o2, k+10, v)))
        (v2, p2) = state.maps.get(o2, K+10)
        self.assertSolver(state, ~p | p2)
        self.assertSolver(state, ~p | (v == v2))

    def test_forall_subset_rev(self):
        state = empty_state()
        o1 = claripy.BVS("O1", 64)
        state.maps[o1] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test1", _length=100, _invariants=[lambda i: claripy.true])
        (v, p) = state.maps.get(o1, K)
        o2 = claripy.BVS("O2", 64)
        state.maps[o2] = Map.new(state, KEY_SIZE, VALUE_SIZE, "test2", _length=10, _invariants=[lambda i: claripy.true])
        state.solver.add(state.maps.forall(o2, lambda k, v: MapHas(o1, k+10, v)))
        (v2, p2) = state.maps.get(o2, K-10)
        self.assertSolver(state, ~p2 | (v == v2))


    def mergeSetup(self, **kwargs):
        state1 = empty_state()
        state2 = empty_state()
        map1 = Map.new(state1, KEY_SIZE, VALUE_SIZE, "map", **kwargs)
        map2 = copy.deepcopy(map1)
        return (state1, state2, map1, map2)

    def test_merge_empty(self):
        (state1, state2, map1, map2) = self.mergeSetup()
        self.assertTrue(map1.can_merge([map2]))
        mapm = map1.merge(state1, [map2], [state2], [X == 0, X == 1])
        self.assertEqual(mapm.meta.key_size, KEY_SIZE)
        self.assertEqual(mapm.meta.value_size, VALUE_SIZE)
        self.assertSolver(state1, mapm.length() == 0)

    def test_merge_leftget(self):
        (state1, state2, map1, map2) = self.mergeSetup(_length=10, _invariants=[lambda i: claripy.true])
        (v1, p1) = map1.get(state1, K)
        state1.solver.add(p1, v1 == 42)
        self.assertTrue(map1.can_merge([map2]))
        (statem, conds, _) = state1.merge(state2)
        mapm = map1.merge(statem, [map2], [state2], conds)
        (vm, pm) = mapm.get(statem, K)
        self.assertSolverUnknown(statem, pm & (vm == 42))
        self.assertSolver(statem, ~conds[0] | (pm & (vm == 42)))

    def test_merge_rightget(self):
        state1 = empty_state()
        state2 = empty_state()
        map1 = Map.new(state1, KEY_SIZE, VALUE_SIZE, "map", _length=10, _invariants=[lambda i: claripy.true])
        map2 = copy.deepcopy(map1)
        (v2, p2) = map2.get(state2, K)
        state2.solver.add(p2, v2 == 42)
        self.assertTrue(map1.can_merge([map2]))
        (statem, conds, _) = state1.merge(state2)
        mapm = map1.merge(statem, [map2], [state2], conds)
        (vm, pm) = mapm.get(statem, K)
        self.assertSolverUnknown(statem, pm & (vm == 42))
        self.assertSolver(statem, ~conds[1] | (pm & (vm == 42)))

    def test_simplify(self):
        state = empty_state()
        x = claripy.BVS("x", 64)
        y = claripy.BVS("y", 64)
        b = claripy.BoolS("b")
        b2 = claripy.BoolS("b2")
        state.solver.add(claripy.If(b, claripy.true, ~b2))
        expr = claripy.If(b, x + 21, claripy.If(b2, 0, y + 10) + 11)
        from kalm import utils
        self.assertSolver(state, utils.simplify(state, expr).structurally_match(21 + claripy.If(b, x, y)))
        z = claripy.BVS("z", 64)
        expr2 = claripy.If(b, z + 8 * x, z + 8 * y)
        self.assertSolver(state, utils.simplify(state, expr2).structurally_match(z + claripy.If(b, 8 * x, 8 * y)))


if __name__ == '__main__':
    unittest.main()
