import ast_util
import reg_util
import spec_reg

def cache(state, addr, reg, id):
    if addr != None:
        addr = state.solver.eval(addr)
    state.globals['cached_addr'] = addr
    state.globals['cached_reg'] = reg
    state.globals['cached_id'] = id



def track_pci_reads(state, base, pci_addr):
    """
    Like track_reads_before but simplified for PCI registers.
    """
    name = reg_util.find_pci_reg_from_base(base, spec_reg.pci_regs)
    data = spec_reg.pci_regs[name]
    reg = reg_util.fetch_reg_and_store(state, name, None, data, pci_addr + base, True)
    return reg

def track_reads_before(state):
    """
    Manages reads of an register. Mainly, initialises register value 
    before first time reads.
    """
    addr = state.inspect.mem_read_address
    reg, index = find_reg_from_addr(state, addr)
    if reg == None:
        return
    # Initialise the register if needed
    data = spec_reg.registers[reg]
    reg_util.fetch_reg_and_store(reg, index, data, addr, state.globals['use_init'])
    return


def track_reads_after(state):
    # print('Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address)
    return

def track_pci_writes(state, base, pci_addr, val):
    """
    Like track_writes_before but simplified for pci registers.
    """
    name = reg_util.find_pci_reg_from_base(base, spec_reg.pci_regs)
    data = spec_reg.pci_regs[name]
    # index is None since no pci registers are indexed
    reg_val = reg_util.fetch_reg_and_store(state, name, None, data, pci_addr + base, True)
    # Check access
    fields = find_fields_on_write(reg_val, val, name, state, spec_reg.pci_regs)
    check_access_write(state, name, reg_val, val, data, fields)
    verify_write(state, fields, name, None, spec_reg.pci_regs)
    reg_util.update_reg(name, None, data, val)
    return



def track_writes_before(state):
    """
    Manages writes to a register. Verifies if the writes
    are legal and appropriate.
    """
    # Find out which register is being written 
    addr = state.inspect.mem_write_address
    reg, index = find_reg_from_addr(state, addr)
    if reg == None:
        return
    data = spec_reg.registers[reg]
    reg_val = reg_util.fetch_reg_and_store(state, reg, index, data, addr, state.globals['use_init'])
    # Check access
    expr = state.inspect.mem_write_expr 
    fields = find_fields_on_write(reg_val, expr, reg, state, spec_reg.registers)
    check_access_write(state, reg, reg_val, expr, data, fields)
    # Verify write against the specification
    verify_write(state, fields, reg, index, spec_reg.registers)
    # If the write is legal, store the new value in state
    # Store to memory will happen automatically.
    reg_util.update_reg(state, reg, index, data, expr)

def track_writes_after(state):
    # print('Write', state.inspect.mem_write_expr, 'to', state.inspect.mem_write_address)
    latest = state.globals['latest_action']
    if latest != None:
        # Apply postcondition
        post = state.globals['legal_actions'][latest]['postcond']
        if post != None:
            _, index = find_reg_from_addr(state, state.inspect.mem_write_address)
            post.applyAST(state, index, spec_reg.registers, spec_reg.pci_regs)
        state.globals['latest_action'] = None

