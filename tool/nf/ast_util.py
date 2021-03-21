import claripy

from enum import Enum
from . import reg_util
from . import spec_reg

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
    DelaySet = 9 # set but after a while
    DelayClear = 10 # clear but after a while; TODO for both Delay*s, need to actually have a delay; but the data sheet often doesn't give one...
    Value = 11
    Actn  = 12

class Node:
    def __init__(self, kind, children):
        self.kind = kind
        self.children = children
    
    def getKind(self):
        return self.kind
    
    def getChild(self, id):
        return self.children[id]

    def getRegisters(self):
        results = []
        for child in self.children:
            if isinstance(child, str):
                results.append(child.split(".", 1)[0])
            if isinstance(child, Node):
                results += child.getRegisters()
        return results

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
            if not (self.children[0].getKind() == AST.Reg and self.children[0].getChild(0) == name):
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
            return (self.children[0].getKind() == AST.Reg and self.children[0].getChild(0) == name)
        else:
            return False
    
    def applyAST(self, state, device, index):
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
                    c.applyAST(state, device, index)
                return 
            else:
                raise Exception("Illegal AST for this function")
        #print(first_child)
        reg, field = first_child.split('.', 1)
        regs_spec = spec_reg.registers
        if reg not in spec_reg.registers.keys():
            regs_spec = spec_reg.pci_regs
        
        new_val = None
        if self.kind == AST.Set or self.kind == AST.DelaySet:
            new_val = 0b1
        elif self.kind == AST.Clear or self.kind == AST.DelayClear:
            new_val = 0b0
        elif self.kind == AST.Write:
            raise Exception("NOT IMPLEMENTED but probably should be")
        reg_util.change_reg_field(state, device, first_child, index, regs_spec, new_val)


    def generateConstraints(self, device, registers, pci_regs, index):
        """
        Generates constraints to quickly check whether propositional
        logic precondition AST on registers is valid.
        :param registers: register spec
        :return: constrained bit vector
        """
        if self.kind == AST.Not:
            return (~self.children[0].generateConstraints(device, registers, pci_regs, index))
        elif self.kind == AST.Reg:
            r, f = self.children[0].split('.', 1)
            spec = registers
            reg_dict = device.regs
            if r not in registers.keys():
                spec = pci_regs
                reg_dict = device.pci_regs
            data = spec[r]
            reg = reg_util.fetch_reg(reg_dict, r, index, data, device.use_init[0])
            start = data['fields'][f]['start']
            end = data['fields'][f]['end']
            return reg[end:start]
        elif self.kind == AST.Or:
            con = claripy.BVV(0,1)
            for c in self.children:
                con = con | c.generateConstraints(device, registers, pci_regs, index)
            return con
        elif self.kind == AST.And:
            con = claripy.BVV(1,1)
            for c in self.children:
                con = con & c.generateConstraints(device, registers, pci_regs, index)
            return con
        else:
            raise Exception("Invalid AST")
