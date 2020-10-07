# Standard/External libraries
import angr
import claripy
from collections import namedtuple

# Us
import binary.bitsizes as bitsizes
import binary.cast as cast
import binary.clock as clock
import binary.utils as utils
from binary.exceptions import SymbexException

class GenericEq(angr.SimProcedure):
    def run(self, a, b, obj_size):
        # Casts
        a = cast.ptr(a)
        b = cast.ptr(b)
        obj_size = cast.size_t(obj_size)
        print(f"!!! generic_eq [a: {a}, b: {b}, obj_size: {obj_size}]")

        # @TODO return something meaningful
        return claripy.BVV(0, bitsizes.bool)
        


class GenericHash(angr.SimProcedure):
    def run(self, obj, obj_size):
        # Casts
        obj = cast.ptr(obj)
        obj_size = cast.size_t(obj_size)
        print(f"!!! generic_hash [obj: {obj}, obj_size: {obj_size}]")

        # @TODO what should we do here ?
        return claripy.BVS("obj_hash", bitsizes.uint32_t)