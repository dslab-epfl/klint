import claripy

from binary import utils
from . import ast_util
from . import spec_act
from . import spec_reg

# TODO: Akvile had put a cache here, which is a good idea since the read-then-write pattern is common;
#       I removed it cause it depended on state.globals, but we should put it back somehow

def __constrain_field(symb, start, end, value):
    """
    Makes the constrain symb[end:start] = value on the state solver.
    """
    if value & (2**(1 + end - start) - 1) != value:
        raise Exception(f"The value {value} does not fit in the specified range {symb}[{end}:{start}].")
    value = claripy.BVV(value, end - start + 1)
    if start == 0:
        if end == symb.size() - 1:
            return value
        return symb[symb.size()-1:end+1].concat(value)
    if end == symb.size() - 1:
        return value.concat(symb[start-1:0])
    return symb[symb.size()-1:end+1].concat(value).concat(symb[start-1:0])

def __init_reg_val_symb(name, data):
    """
    Creates and returns a Symbolic Bit Vector for the identified register based on 
    initial register field values
    :param name: the name of the register
    :param data: dictionary associated with the register reg
    :return: the symbolic register value 
    """
    symb = claripy.BVS(name, data['length'])
    last = 0 # Last unconstrained bit
    for field, info in data['fields'].items():
        if info['init'] == 'X': # Floating value can be modeled as uncontrained
            last = info['end'] + 1
            continue
        if last != info['start']: # There is an implicit Reserved block
            symb = __constrain_field(symb, last, info['start'] - 1, 0)
            last = info['start']    
        symb = __constrain_field(symb, info['start'], info['end'], info['init'])
        last = info['end'] + 1
    if last != data['length']: # There is a reserved field at the end
        symb = __constrain_field(symb, last, data['length'] - 1, 0)
    return symb

def __init_reg_val_con(data):
    """
    Creates and returns a Bit Vector for the indentified register based on
    initial register field values. Returns None if the register cannot be
    made concrete.
    :param data: dictionary associated with the register
    :return: BVV or None
    """
    value = 0
    for field, info in data['fields'].items():
        if info['init'] == 'X': # Floating value can be modeled as uncontrained
            return None   
        value = value | (info['init'] << info['start'])
    bvv = claripy.BVV(value, data['length'])
    return bvv

def get_pci_reg(base, spec): 
    for name, info in spec.items():
        b, m, _ = info['addr'][0]
        assert(m == 0)
        if b == base:
            return name
    raise Exception(f"PCI register with address 0x{base:x} is not in the spec.")

def find_reg_from_addr(state, addr, _cache={}):
    if len(_cache) == 0:
        for reg, data in spec_reg.registers.items():
            idx = 0
            for b, m, l in data['addr']:
                for n in range(0, l+1-idx):
                    _cache[b + n*m] = (reg, n+idx)
                idx += l + 1
    """
    Finds which register the address refers to.
    :return: the name of the register and its index.
    """
    # Optimization: if addr isn't symbolic then deal with it quickly
    if not isinstance(addr, claripy.ast.Base) or not addr.symbolic:
        conc_addr = state.solver.eval(addr)
        cached = _cache.get(conc_addr, None)
        if cached is not None:
            return cached
        for reg, data in spec_reg.registers.items():
            len_bytes = data['length'] // 8
            idx = 0
            for b, m, l in data['addr']:
                high = b + (l-idx)*m + len_bytes
                if b <= conc_addr and conc_addr < high:
                    reg_index = 0 if m == 0 else ((conc_addr - b) / m + idx)
                    if int(reg_index) == reg_index:
                        reg_index = int(reg_index) # they compare as equal but without this reg_index is still a float
                        #print(f"{reg}[{reg_index}]")
                        return reg, reg_index
                idx += l + 1

    raise Exception("Need to double-check logic below for symbolic indices...")

    n = claripy.BVS("n", 64)
    for reg, data in spec_reg.registers.items():
        len_bytes = data['length'] // 8
        p = 0
        for b, m, l in data['addr']:
            low = b + (n-p)*m
            high = low + len_bytes
            constraint = (n - p >= 0) & (n <= l) & (low <= addr) & (addr < high)
            if utils.definitely_false(state.solver, constraint):  # Continue the search
                p += l + 1
                continue
            if m != 0:
                n_con = state.solver.eval(n, extra_constraints=[constraint])
                #if not (n_con in state.globals['indices']):
                #    state.globals['indices'] += [n_con]
                #print(f"{reg}[{n_con}]")
                return reg, n_con
            #print(f"{reg}")
            return reg, None
    raise Exception(f"Cannot find register at {addr}.")

def is_reg_indexed(data):
    _, m, _ = data['addr'][0]
    return (m != 0)

def fetch_reg(reg_dict, reg, index, data, use_init):
    """
    Fetches register from state global store. Initialises it if needed.
    """
    if reg in reg_dict:
        d = reg_dict[reg]
        if is_reg_indexed(data):
            if index in d.keys():
                return d[index]
            #else:
            #    raise "what do I do here?"
        else:
            return d
    if use_init:
        reg_bv = __init_reg_val_con(data)
        if reg_bv == None:
            # If a concrete value cannot be created, try symbolic
            reg_bv = __init_reg_val_symb(reg, data)
    else:
        reg_bv = claripy.BVS(reg, data['length'])
    update_reg(reg_dict, reg, index, data, reg_bv)
    return reg_bv

def fetch_reg_field(name, index, data, use_init):
    """
    Fetches a particular field of the identified register
    :param name: name of the form REG.FIELD
    :param data: dictionary associated with REG
    """
    r, f = name.split('.', 1)
    reg = fetch_reg(r, index, data, use_init)
    field_data = data['fields'][f]
    return reg[field_data['end']:field_data['start']]

def update_reg(reg_dict, reg, index, data, expr):
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

def find_fields_on_write(state, prev, new, reg, spec):
    """
    Finds which named fields of the register have been changed and
    returns this information as a list.
    """
    data = spec[reg]
    fields = []
    for field, info in data['fields'].items():
        s = info['start']
        e = info['end']
        if utils.can_be_true(state.solver, prev[e:s] != new[e:s]):
            p = prev[e:s]
            n = new[e:s]
            fields += [(field, p, n)]
    return fields

def check_access_write(old_val, new_val, reg, data, fields):
    """
    Determines which fields are written and whether it is legal
    to do so.
    """
    reg_access = data['access']
    if len(fields) == 0 and reg_access == spec_reg.Access.RO:
        # NOTE: This permits writing to reserved fields
        raise Exception(f"Illegal attempt to write to register {reg}")
    for i, f_info in enumerate(fields):
        (f, p, n) = f_info
        field_access = data['fields'][f]['access']
        if field_access == spec_reg.Access.IW:
            fields[i] = (fields[i][0],fields[i][1],fields[i][1]) # new is prev
            return
        illegal = (field_access == spec_reg.Access.NA)
        illegal |= (field_access == spec_reg.Access.RO)
        if illegal:
            raise Exception(f"Illegal attempt to write to {reg}.{f}")

def change_reg_field(state, device, name, index, registers, new):
    """
    Changes a single field in a register and saves the new value.
    :param name: register indentifier of the form REG.FIELD
    :param register: register spec
    :param new: new field value. If the field is to be made 
    symbolic, should be 'X'. 
    """
    reg, field = name.split('.', 1)
    data = registers[reg]
    prev = -1
    dev_regs = device.regs
    if registers == spec_reg.pci_regs:
        dev_regs = device.pci_regs
    reg_old = fetch_reg(dev_regs, reg, index, data, device.use_init[0])
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
        reg_new = claripy.BVV(val, data['length'])
    else:
        if new == 'X':
            raise "oops"
        value_len = f_info['end'] - f_info['start'] + 1
        if f_info['start'] == 0:
            reg_new = claripy.BVV(new, value_len)
        else:
            reg_new = claripy.BVV(new, value_len).concat(reg_old[f_info['start']-1:0])
        if f_info['end'] < data['length'] - 1:
            reg_new = reg_old[data['length']-1:f_info['end']+1].concat(reg_new)
    update_reg(dev_regs, reg, index, data, reg_new)


def verify_write(state, device, fields, reg, index, reg_dict, _cache={}):
    """
    Verifies if the write can be matched to an action.
    Raises an exception if it can't be matched.
    """
    if len(_cache) == 0:
        for action, info in spec_act.actions.items():
            for r in info['action'].getRegisters():
                if r in _cache:
                    _cache[r].append((action, info))
                else:
                    _cache[r] = [(action, info)]

    counter = device.counter[0]
    for f_info in fields:
        (f, prev, new) = f_info
        n = state.solver.eval(new)
        # Actions which preconditions fail - useful for debuging
        rejected = []
        # The write to this field is invalid until a matching 
        # action is found
        valid = False
        if reg_dict[reg]['fields'][f]['access'] == spec_reg.Access.IW:
            # Validating this field is optional
            valid = True
        for action, info in _cache.get(reg, []):
            # Does the action match writing to this field?
            action_matches = False
            if reg_dict[reg]['fields'][f]['end'] != reg_dict[reg]['fields'][f]['start']:
                action_matches = info['action'].isWriteFieldCorrect(state, f"{reg}.{f}", new)
            elif (n == 1 and info['action'].isFieldSetOrCleared(f"{reg}.{f}", ast_util.AST.Set)):
                action_matches = True
            elif (n == 0 and info['action'].isFieldSetOrCleared(f"{reg}.{f}", ast_util.AST.Clear)):
                action_matches = True

            if not action_matches:
                continue
            
            # If there is no precondition, the action is valid
            precond_sat = True
            if info['precond'] != None:
                con = info['precond'].generateConstraints(device, spec_reg.registers, spec_reg.pci_regs, index)
                precond_sat = state.solver.eval(con)
            if not precond_sat:
                rejected += [action]
                continue
            valid = True
            print("Action: ", action)
            if action == 'Initiate Software Reset':
                device.use_init[0] = True
            device.latest_action[0] = action
            if action in device.actions.keys():
                # We have seen this action before 
                device.actions[action] = device.actions[action] + [counter]
            else:
                device.actions[action] = [counter]
        if valid:
            continue
        if len(rejected) == 0:
            raise Exception(f"Cannot validate writing to {reg}.{f}. There are no actions that match writing to this field.")
        if not valid:
            raise Exception(f"Cannot validate writing to {reg}.{f}. Matching but rejected actions: {rejected}. Maybe the precondition is not satisfied for one of them?")
    # If we did not raise any exception, that means we are able to match
    # concurrent writes to actions. Increment counter to establish
    # action order.
    device.counter[0] = counter + 1
