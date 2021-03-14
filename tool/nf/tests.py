
import angr
import unittest
from spec_reg import Access
import ast_util

global_state = {
    "Test field enabled" : 
        ast_util.Node(ast_util.AST.Reg,["TEST.FIELD"])
}

registers = {
    'TEST' : {
        'base'   : 0x3000,
        'length' : 32,
        'id_mul' : 0, 
        'id_lim' : 0, 
        'access' : Access.RW, # default access for this register 
        'fields'  : {
            'FIELD' : {
                'access' : Access.RW,
                'init'   : 0b1,
                'start'  : 0,
                'end'    : 0
            },
            'Reserved' : {
                'access' : Access.RO,
                'init'   : 0x0,
                'start'  : 1,
                'end'    : 31
            }
        }
    }
}

class TestAstUtilMethods(unittest.TestCase):

    def test_is_field_set(self):
        tree = ast_util.Node(ast_util.AST.Set, [
            ast_util.Node(ast_util.AST.Reg, ["Test"])
        ])
        self.assertTrue(tree.isFieldSetOrCleared("Test", ast_util.AST.Set))
        self.assertFalse(tree.isFieldSetOrCleared("Test", ast_util.AST.Clear))
        self.assertFalse(tree.isFieldSetOrCleared("NotTest", ast_util.AST.Set))

    def test_is_field_cleared(self):
        tree = ast_util.Node(ast_util.AST.Clear, [
            ast_util.Node(ast_util.AST.Reg, ["Test"])
        ])
        self.assertTrue(tree.isFieldSetOrCleared("Test", ast_util.AST.Clear))
        self.assertFalse(tree.isFieldSetOrCleared("Test", ast_util.AST.Set))
        self.assertFalse(tree.isFieldSetOrCleared("NotTest", ast_util.AST.Clear))
    
    def test_generate_contraints(self):
        proj = angr.Project('/bin/true', auto_load_libs=False, use_sim_procedures=False)
        state = angr.factory.AngrObjectFactory(proj).blank_state()
        state.globals['device_addr'] = 0x00000
        state.globals['TEST'] = state.solver.BVV(0, 32)
        cond = ast_util.Node(ast_util.AST.Not, [
            ast_util.Node(ast_util.AST.Reg, ["TEST.FIELD"])
        ])
        constraint = cond.generateConstraints(registers, None)
        self.assertTrue(state.solver.eval(constraint) == 1)
        cond = ast_util.Node(ast_util.AST.And, [
            ast_util.Node(ast_util.AST.Reg, ["TEST.FIELD"]),
            ast_util.Node(ast_util.AST.Not, [
            ast_util.Node(ast_util.AST.Reg, ["TEST.FIELD"])
            ])
        ])
        constraint = cond.generateConstraints(registers, None)
        self.assertTrue(state.solver.eval(constraint) == 0)
        cond = ast_util.Node(ast_util.AST.Clear, [
            ast_util.Node(ast_util.AST.Reg, ["Test"])
        ])
        with self.assertRaises(Exception):
            cond.generateConstraints(registers, None)

    def test_check_validity(self):
        proj = angr.Project('/bin/true', auto_load_libs=False, use_sim_procedures=False)
        state = angr.factory.AngrObjectFactory(proj).blank_state()
        state.globals['device_addr'] = 0x00000
        state.globals['TEST'] = state.solver.BVV(0, 32)
        cond = ast_util.Node(ast_util.AST.Not, [
            ast_util.Node(ast_util.AST.Reg, ["TEST.FIELD"])
        ])
        self.assertTrue(cond.checkValidity(state, registers, 
            global_state, "", True, None))
        cond = ast_util.Node(ast_util.AST.Or, [
            ast_util.Node(ast_util.AST.Glob, ["Test field enabled"]),
            ast_util.Node(ast_util.AST.Not, [
            ast_util.Node(ast_util.AST.Reg, ["TEST.FIELD"])
            ])
        ])
        self.assertTrue(cond.checkValidity(state, registers, 
            global_state, "", True, None))
        

if __name__ == '__main__':
    unittest.main(verbosity=2)