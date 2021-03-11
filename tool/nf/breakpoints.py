import ast_util
import reg_util
import spec_reg

def cache(state, addr, reg, id):
    if addr != None:
        addr = state.solver.eval(addr)
    state.globals['cached_addr'] = addr
    state.globals['cached_reg'] = reg
    state.globals['cached_id'] = id

def find_reg_from_addr(state, addr):
    """
    Finds which register the address refers to.
    :return: the name of the register and its index.
    """
    if state.solver.eval(addr) == state.globals['cached_addr']:
        return state.globals['cached_reg'], state.globals['cached_id']
    # Is this a register access?
    dev_addr = state.globals['device_addr']
    temp_state = state.copy()
    temp_state.solver.add(dev_addr <= addr)
    temp_state.solver.add(addr < dev_addr + 1024*128)
    # print(addr, cached_addr)
    if temp_state.satisfiable() == False:
        # Not a register access
        return None, None
    for reg, data in spec_reg.registers.items():
        len_bytes = int(data['length']/8)
        p = 0
        for b, m, l in data['addr']:
            temp_state = state.copy()
            n = temp_state.solver.BVS("n", 64)
            temp_state.solver.add(n - p >= 0)
            temp_state.solver.add(n <= l)
            low = dev_addr + b + (n-p)*m
            high = low + len_bytes
            temp_state.solver.add(addr < high)
            temp_state.solver.add(low <= addr)
            if temp_state.satisfiable() == False: # Continue the search
                p += l + 1
                continue
            if m != 0:
                n_con = temp_state.solver.eval(n)
                if not (n_con in state.globals['indices']):
                    state.globals['indices'] += [n_con]
                cache(state, addr, reg, n_con)
                print(f"{reg}[{n_con}]")
                return reg, n_con
            cache(state, addr, reg, None)
            print(f"{reg}")
            return reg, None
    raise Exception(f"Cannot find register at {addr}.")

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
    reg_util.fetch_reg_and_store(state, reg, index, data, addr, state.globals['use_init'])
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
    reg_util.update_reg(state, name, None, data, val)
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

