import angr
import claripy
import spec_glo
import spec_reg
import spec_act
import breakpoints
import log
import manager
    
# Make sure spec is OK
spec_reg.validate_registers(spec_reg.registers)
spec_reg.validate_registers(spec_reg.pci_regs)
spec_act.validate_actions()
spec_glo.validate_globals()

# Must use 'TN_STRIP=/bin/true TN_DEBUG=0 TN_CFLAGS=-g make' command to generate the binary with symbols

proj = angr.Project('../tinynf/code/tinynf', auto_load_libs=False, use_sim_procedures=False)

# Note: angr wraps the Claripy AST instances in an object that 
# tracks stuff, which is helpful for some binary analyses but not 
# for us so we have to call '.ast' on the arguments to 'run' to 
# get the original Claripy AST
class TnMemAllocate(angr.SimProcedure):
    def run(self, size, out_addr):
        simstate = self.state
        size_val = simstate.solver.eval(size.ast)
        addr = simstate.heap.malloc(size_val)
        # TODO: make address aligned to the size
        if addr == 0:
            return 0
        simstate.memory.store(addr, simstate.solver.BVV(0, size_val*8), endness=simstate.arch.memory_endness) 
        simstate.memory.store(out_addr.ast, simstate.solver.BVV(addr, 8*8), endness=simstate.arch.memory_endness) 
        return 1
class TnMemFree(angr.SimProcedure):
    def run(self, addr):
        raise "TODO"
class TnMemPhysToVirt(angr.SimProcedure):
    def run(self, addr, size, out_virt_addr):
        self.state.mem[out_virt_addr.ast].uint64_t = addr.ast # TODO more general case
        return 1
class TnMemVirtToPhys(angr.SimProcedure):
    def run(self, addr, out_phys_addr):
        self.state.mem[out_phys_addr.ast].uint64_t = addr.ast # TODO more general case
        return 1
class TnSleepUS(angr.SimProcedure):
    def run(self, microseconds):
        # The function just completes
        return None
class TnPciRead(angr.SimProcedure):
    def run(self, addr, reg):
        print("Reading ", addr, " register ", reg)
        value = self.state.solver.eval(reg.ast)
        reg = breakpoints.track_pci_reads(self.state, value, addr.ast)
        print(reg)
        if reg.op == 'BVS':
            return reg
        return self.state.solver.eval(reg)
class TnPciWrite(angr.SimProcedure):
    def run(self, addr, reg, val):
        print("Writing ", addr, " register ", reg, "Value ", val)
        value = self.state.solver.eval(reg.ast)
        breakpoints.track_pci_writes(self.state, value, addr.ast, 
            val.ast)
        return None

ext_funcs = {
  'tn_mem_allocate': TnMemAllocate,
  'tn_mem_free': TnMemFree,
  'tn_mem_phys_to_virt': TnMemPhysToVirt,
  'tn_mem_virt_to_phys': TnMemVirtToPhys,
  'tn_sleep_us': TnSleepUS,
  'tn_pci_read': TnPciRead,
  'tn_pci_write': TnPciWrite, 
}

for (fname, fproc) in ext_funcs.items():
    proj.hook_symbol(fname, fproc())

def verify_prom_without_init():
    base_state = manager.get_base_state(proj)
    prom_state = manager.get_promiscous_state(proj, base_state, None)
    manager.run_validation(proj, prom_state, spec_glo.promiscous, spec_act.promiscous, 1)

def verify_receive_enable_without_init():
    base_state = manager.get_base_state(proj)
    receive_state = manager.get_receive_init_state(proj, base_state, None, None)
    manager.run_validation(proj, receive_state, spec_glo.enable_receive_queue, spec_act.enable_receive_queue, 1)

def verify_receive_enable_with_init():
    base_state = manager.get_base_state(proj)
    receive_state = manager.get_receive_init_state(proj, base_state, None, None)
    receive_state.globals['use_init'] = True
    manager.run_validation(proj, receive_state, spec_glo.enable_receive_queue, spec_act.enable_receive_queue, 1)

def verify_receive_enable_with_agent_init():
    base_state = manager.get_base_state(proj)
    concrete_agent, new_state = manager.get_con_tn_agent_ptr(proj, base_state)
    receive_state = manager.get_receive_init_state(proj, new_state, concrete_agent, None)
    receive_state.globals['use_init'] = True
    manager.run_validation(proj, receive_state, spec_glo.enable_receive_queue, spec_act.enable_receive_queue, 1)

def verify_transmit_with_init():
    base_state = manager.get_base_state(proj)
    receive_state = manager.get_transmit_init_state(proj, base_state, None, None)
    receive_state.globals['use_init'] = True
    manager.run_validation(proj, receive_state, spec_glo.enable_transmit_queue, spec_act.enable_transmit_queue, 1)

def verify_transmit_with_agent_init():
    base_state = manager.get_base_state(proj)
    concrete_agent, new_state = manager.get_con_tn_agent_ptr(proj, base_state)
    receive_state = manager.get_transmit_init_state(proj, new_state, concrete_agent, None)
    receive_state.globals['use_init'] = True
    manager.run_validation(proj, receive_state, spec_glo.enable_transmit_queue, spec_act.enable_transmit_queue, 1)

def verify_device_init():
    base_state = manager.get_base_state(proj)
    concrete_dev, new_state = manager.get_con_tn_net_device_ptr(proj, base_state)

def enable_queue_demo():
    verify_receive_enable_without_init()
    verify_receive_enable_with_init()
    verify_receive_enable_with_agent_init()