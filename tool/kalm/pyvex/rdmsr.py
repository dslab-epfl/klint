from pyvex.lifting.util import Type
from pyvex.lifting.util.instr_helper import Instruction
from pyvex.lifting.util.lifter_helper import GymratLifter

# Handle RDMSR, specifically register 0xCE which contains the clock frequency

class Instruction_RDMSR(Instruction):
    name = "RDMSR"
    bin_format = "0000111100110010" # 0x0F32
    def compute_result(self):
        def amd64g_rdmsr(state, msr):
            # For now we only emulate the clock frequency
            if not msr.structurally_match(claripy.BVV(0xCE, 32)):
                raise Exception("Unknown R for RDMSR")
            high = claripy.BVS("msr_high", 32)
            low = claripy.BVS("msr_low", 32)
            low = low[31:16].concat(clock.frequency_num[7:0]).concat(low[7:0])
            state.regs.edx = high
            state.regs.eax = low
            return 0

        return self.ccall(Type.int_32, amd64g_rdmsr, [self.get("ecx", Type.int_32)])
class RDMSRSpotter(GymratLifter):
    instrs = [Instruction_RDMSR]