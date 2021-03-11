from enum import Enum
from . import reg_util
from .log import print_informatively

class AST(Enum):
    Not   = 0
    Or    = 1
    And   = 2
    Reg   = 3
    Set   = 4
    Clear = 5
    Global  = 6
    Write = 7 # Used for fields
    Check = 8 # Apply a check to the arguments
    MkSym = 9 # Make a field symbolic 
    Value = 10 
    Actn  = 11

class Node:
    def __init__(self, kind, children):
        self.kind = kind
        self.children = children
    
    def getKind(self):
        return self.kind
    
    def getChild(self, id):
        return self.children[id]

    def isWriteFieldCorrect(self, state, name, value):
        """
        Checks whether this AST corresponds to a legal write
        to a specific register.
        :param state: Angr state
        :param name: identifier of a register field
        :param value: value to be written into the field
        :return: bool
        """
        if self.kind == AST.Write:
            if not (self.children[0].getKind() == AST.Reg and 
                self.children[0].getChild(0) == name):
                return False
            if self.children[1].getKind() != AST.Value:
                raise Exception("Illegal AST for this function")
            valid = self.children[1].getChild(0)(value)
            return (state.solver.eval(valid) == True)
        else:
            return False
    
    def isFieldSetOrCleared(self, name, kind):
        """
        Checks wether this AST corresponds to setting or clearing
        of a specified register.
        :param name: identifier of the form REG.FIELD
        :param kind: AST.Clear or AST.Set
        :return: bool
        """
        if self.kind == kind:
            return (self.children[0].getKind() == AST.Reg and 
                self.children[0].getChild(0) == name)
        else:
            return False
    
    def applyAST(self, state, index, registers, pci_regs):
        """
        Applies the AST to the state's registers.
        :param state: Angr state
        :param index: index to be used for all indexed registers
        in this AST
        """
        first_child = self.children[0].getChild(0)
        if self.children[0].kind != AST.Reg:
            if self.kind == AST.And:
                for c in self.children:
                    c.applyAST(state, index, registers, pci_regs)
                return 
            else:
                raise Exception("Illegal AST for this function")
        print(first_child)
        reg, field = first_child.split('.', 1)
        spec = pci_regs
        addr = state.globals['pci_address']
        if reg in registers.keys():
            spec = registers
            addr = state.globals['device_addr']
        
        if self.kind == AST.Set:
            reg_util.change_reg_field(state, first_child, 
                index, spec, addr, 0b1)
        elif self.kind == AST.Clear:
            reg_util.change_reg_field(state, first_child, 
                index, spec, addr, 0b0)
        elif self.kind == AST.MkSym:
            reg_util.change_reg_field(state, first_child, 
                index, spec, addr, 'X')
        elif self.kind == AST.Write:
            raise Exception("NOT IMPLEMENTED but probably should be")


    def generateConstraints(self, state, registers, pci_regs, index):
        """
        Generates constraints to quickly check whether propositional
        logic precondition AST on registers is valid.
        :param registers: register spec
        :return: constrained bit vector
        """
        if self.kind == AST.Not:
            return (~self.children[0].generateConstraints(state, registers, pci_regs, index))
        elif self.kind == AST.Reg:
            r, f = self.children[0].split('.', 1)
            spec = registers
            if not (r in registers.keys()):
                spec = pci_regs
            data = spec[r]
            reg = reg_util.fetch_reg(state, r, index, data, state.globals['use_init'])
            start = data['fields'][f]['start']
            end = data['fields'][f]['end']
            return reg[end:start]
        elif self.kind == AST.Or:
            con = state.solver.BVV(0,1)
            for c in self.children:
                con = con | c.generateConstraints(state, registers, pci_regs, index)
            return con
        elif self.kind == AST.And:
            con = state.solver.BVV(1,1)
            for c in self.children:
                con = con & c.generateConstraints(state, registers, pci_regs, index)
            return con
        else:
            raise Exception("Invalid AST")
    
    def checkValidity(self, state, registers, global_state, indent, 
        hope, index):
        """
        Check if the propositional logic AST on global states and 
        registers are valid and generate a readable trace.
        :return: bool
        """
        if self.kind == AST.Not:
            print(f"{indent}Checking AST.Not ..")
            result = self.children[0].checkValidity(state, 
                registers, global_state, indent+"  ", not hope, index)
            if result:
                print_informatively(False, hope, f"{indent} .. AST.Not does not hold.")
                return False
            print_informatively(True, hope, f"{indent}.. AST.Not holds.")
            return True            
        elif self.kind == AST.Reg:
            r, f = self.children[0].split('.', 1)
            data = registers[r]
            start = data['fields'][f]['start']
            end = data['fields'][f]['end']
            if start != end:
                raise Exception(f"""While checking {r}.{f}: Properties 
            on fields should be implemented using AST.Check.""")
            reg = reg_util.fetch_reg(state, r, index, data, state.globals['use_init'])
            val = state.solver.eval(reg[end:start])
            if val:
                print_informatively(True, hope, f"{indent}Check for the field {r}.{f} holds.")
                return True
            print_informatively(False, hope, f"{indent}Check for the field {r}.{f} does not hold.")
            return False
        elif self.kind == AST.Global:
            p = self.children[0]
            print(f"{indent}Checking global property {p} ..")
            tree = global_state[p]
            result = tree.checkValidity(state, registers, 
            global_state, indent + "  ", hope, index)
            if result:
                print_informatively(True, hope, f"{indent}.. {p} holds.")
                return True
            print_informatively(False, hope, f"{indent}.. {p} does not hold.")
            return False
        elif self.kind == AST.Or:
            print(f"{indent}Checking AST.Or ..")
            result = False
            for c in self.children:
                result = result | c.checkValidity(state, registers, 
                    global_state, indent+"  ", hope, index)
            if result:
                print_informatively(True, hope, f"{indent}.. AST.Or holds.")
                return True
            print_informatively(False, hope, f"{indent}.. AST.Or does not hold.")
            return False
        elif self.kind == AST.And:
            print(f"{indent}Checking AST.And ..")
            result = True
            for c in self.children:
                result = result & c.checkValidity(state, registers,
                    global_state, indent+"  ", hope, index)
            if result:
                print_informatively(True, hope, f"{indent}.. AST.And holds.")
                return True
            print_informatively(False, hope, f"{indent}.. AST.And does not hold.")
            return False
        elif self.kind == AST.Check:
            lmd = self.children[0]
            arg_len = len(self.children) - 1
            args = [None]*arg_len
            for i in range(arg_len):
                name = self.children[i+1].getChild(0)
                r, f = name.split('.', 1)
                data = registers[r]
                if index == None and reg_util.is_reg_indexed(data):
                    print_informatively(False, hope, 
                        f"""{indent}The property does not hold 
                        (property expects indexed registers but none 
                        were used).""")
                    return False
                args[i] = reg_util.fetch_reg_field(state, name, 
                    index, data, state.globals['use_init'])
            bv = lmd(args)
            sols = state.solver.eval_upto(bv, 2)
            if len(sols) == 2 and hope:
                raise Exception(f"""Property can be both true and false!
                Args given to lambda: {args}.""")
            if sols[0]:
                print_informatively(True, hope, f"{indent}The property holds.")
                return True
            print_informatively(False, hope, f"{indent}The property does not hold.")
            return False
        elif self.kind == AST.Actn:
            action_name = self.children[0]
            result = action_name in state.globals.keys()
            if result:
                print_informatively(True, hope, f"{indent}The action {action_name} was performed.")
                return True
            print_informatively(False, hope, f"{indent}The action {action_name} was not performed.")
            return False
        else:
            raise Exception("Invalid AST") 
