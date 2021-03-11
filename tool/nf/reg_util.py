def __constrain_field(symb, state, start, end, value):
    """
    Makes the constrain symb[end:start] = value on the state solver.
    """
    if value & (2**(1 + end - start) - 1) != value:
        raise Exception(f"The value {value} does not fit in the specified range {symb}[{end}:{start}].")
    state.solver.add(symb[end:start] == value)
    if state.satisfiable() == False:
        raise Exception(f"Constraint {symb}[{end}:{start}] = {value} leads to contradiction.")

def __init_reg_val_symb(state, name, data):
    """
    Creates and returns a Symbolic Bit Vector for the identified register based on 
    initial register field values
    :param state: state on which the register values are constrained
    :param name: the name of the register
    :param data: dictionary associated with the register reg
    :return: the symbolic register value 
    """
    symb = state.solver.BVS(name, data['length'])
    last = 0 # Last unconstrained bit
    for field, info in data['fields'].items():
        if info['init'] == 'X': # Floating value can be modeled as uncontrained
            last = info['end'] + 1
            continue
        if last != info['start']: # There is an implicit Reserved block
            __constrain_field(symb, state, last, info['start'] - 1, 0)
            last = info['start']    
        __constrain_field(symb, state, info['start'], info['end'], info['init'])
        last = info['end'] + 1
    if last != data['length']: # There is a reserved field at the end
        __constrain_field(symb, state, last, data['length'] - 1, 0)
    return symb

def __init_reg_val_con(state, data):
    """
    Creates and returns a Bit Vector for the indentified register based on
    initial register field values. Returns None if the register cannot be
    made concrete.
    :param state: state on which the register values are constrained
    :param data: dictionary associated with the register
    :return: BVV or None
    """
    value = 0
    for field, info in data['fields'].items():
        if info['init'] == 'X': # Floating value can be modeled as uncontrained
            return None   
        value = value | (info['init'] << info['start'])
    bvv = state.solver.BVV(value, data['length'])
    return bvv

def is_reg_indexed(data):
    _, m, _ = data['addr'][0]
    return (m != 0)

def fetch_reg(state, reg_dict, reg, index, data, use_init):
    """
    Fetches register from state global store. Initialises it if needed.
    """
    if reg in reg_dict:
        d = reg_dict[reg]
        if is_reg_indexed(data):
            if index in d.keys():
                return d[index]
            else:
                raise "what do I do here?"
        else:
            return d
    if use_init:
        reg_bv = __init_reg_val_con(state, data)
        if reg_bv == None:
            # If a concrete value cannot be created, try symbolic
            reg_bv = __init_reg_val_symb(state, reg, data)
    else:
        reg_bv = state.solver.BVS(reg, data['length'])
    update_reg(state, reg_dict, reg, index, data, reg_bv)
    return reg_bv

def fetch_reg_and_store(state, reg, index, data, addr, use_init):
    """
    Create an initial register value and store it in the memory.
    If the register has already been initialised, return it.
    Try to make it concrete if possible.
    :param data: dictionary associated with the register reg
    :return: the register's value
    """
    reg_bv = fetch_reg(state, reg, index, data, use_init)
    # store the initialised value but be careful not to trigger other breakpoints
    state.memory.store(addr, reg_bv, disable_actions=True, inspect=False, endness=state.arch.memory_endness)
    return reg_bv

def fetch_reg_field(state, name, index, data, use_init):
    """
    Fetches a particular field of the identified register
    :param name: name of the form REG.FIELD
    :param data: dictionary associated with REG
    """
    r, f = name.split('.', 1)
    reg = fetch_reg(state, r, index, data, use_init)
    field_data = data['fields'][f]
    return reg[field_data['end']:field_data['start']]

def update_reg(state, reg_dict, reg, index, data, expr):
    """
    Update register value in the state.
    :param data: dictionary associated with the register reg
    """
    if not is_reg_indexed(data):
        reg_dict[reg] = expr
    elif reg in reg_dict:
        reg_dict[reg][index] = expr
    else:
        reg_dict[reg] = {index: expr}

def change_reg_field(state, name, index, registers, base_addr, new):
    """
    Changes a single field in a register and saves the new value
    in memory and in state.
    :param name: register indentifier of the form REG.FIELD
    :param register: register spec
    :param addr: base address for the spec, either device or pci
    :param new: new field value. If the field is to be made 
    symbolic, should be 'X'. 
    """
    reg, field = name.split('.', 1)
    data = registers[reg]
    addr = base_addr
    prev = -1
    if index != None:
        for b, m, l in data['addr']:
            if index > l:
                prev = l
                continue
            addr += b + m*(index - prev - 1)
    else:
        b, _, _ = data['addr'][0]
        addr += b
    reg_old = fetch_reg_and_store(state, reg, index, data, addr, state.globals['use_init'])
    reg_new = None
    f_info = data['fields'][field]
    if reg_old.op == 'BVV' and new != 'X':
        val = 0
        if f_info['start'] > 0:
            before = state.solver.eval(reg_old[f_info['start']-1:0])
            val = val | before
        val = val | (new << f_info['start'])
        if f_info['end'] < data['length'] - 1:
            after = state.solver.eval(reg_old[data['length']-1:f_info['end']+1])
            val = val | (after << f_info['end']+1)
        reg_new = state.solver.BVV(val, data['length'])
    else:
        reg_new = state.solver.BVS(reg, data['length'])
        if f_info['start'] > 0:
            state.solver.add(reg_new[f_info['start']-1:0] == 
                reg_old[f_info['start']-1:0])
        if new != 'X':
            state.solver.add(reg_new[f_info['end']:f_info['start']] == new)
        if f_info['end'] < data['length'] - 1:
            state.solver.add(reg_new[
                    data['length']-1:f_info['end']+1
                ] == reg_old[
                    data['length']-1:f_info['end']+1
                ])
    state.memory.store(addr, reg_new, disable_actions=True, inspect=False, endness=state.arch.memory_endness)
    update_reg(state, reg, index, data, reg_new)