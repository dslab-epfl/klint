import angr
import spec_reg
import spec_glo
import spec_act
import breakpoints
import log

def __run_symbex(proj, state, actions):
    state.globals['counter'] = 0
    state.globals['latest_action'] = None
    state.globals['indices'] = []
    state.globals['legal_actions'] = actions
    breakpoints.cache(state, None, None, None)

    state.inspect.b('mem_read', when=angr.BP_AFTER, action=breakpoints.track_reads_after)
    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=breakpoints.track_reads_before)
    state.inspect.b('mem_write', when=angr.BP_AFTER, action=breakpoints.track_writes_after)
    state.inspect.b('mem_write', when=angr.BP_BEFORE, action=breakpoints.track_writes_before)

    simgr = proj.factory.simgr(state)
    simgr.use_technique(angr.exploration_techniques.DFS())    

    simgr.run()
    return simgr.deadended

def run_validation(proj, state, properties, actions, expect):
    deadended = __run_symbex(proj, state, actions)
    cc = proj.factory.cc()
    print(f"""\n 
    Symbex done!
    """)
    total = len(deadended)
    passed = 0
    for i,s in enumerate(deadended):
        print(f"\nVerifying state {i+1}/{total}")
        ret = s.solver.eval(cc.get_return_val(s))
        hope = (ret == expect)
        if hope:
            print(f"The state returned {ret}, expect all the properties to hold.")
        else:
            print(f"The state returned {ret}, expect that some properties do not hold.")
        indices = state.globals['indices']
        if len(indices) == 0:
            print(f"\nThe function did not use indexed registers.")
            result = properties.checkValidity(s, spec_reg.registers, 
                spec_glo.global_state, "  ", hope, None)
            if result == hope: 
                passed += 1
                log.print_green("State passed property verification!")
            else:
                log.print_red("State did not pass property verification!")
        else:
            print(f"\nThe function used indexed registers {indices}.")
            result = True
            for index in indices:
                print(f"Checking properties for index {index}:")
                res = properties.checkValidity(s, spec_reg.registers, 
                    spec_glo.global_state, "  ", hope, index)
                result = result & res
            if result == hope:
                passed += 1 
                log.print_green("State passed property verification!")
            else:
                log.print_red("State did not pass property verification!")
    print(f"\n {passed}\{total} states passed the verification.")

def get_base_state(proj):
    simstate = angr.factory.AngrObjectFactory(proj).blank_state()
    mem_end = simstate.arch.memory_endness

    # IMPORTANT NOTE: need to register the plugin with the name 'heap' or it will break
    simstate.register_plugin("heap", 
    angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc(
        heap_size = 17000000
    ))
    # Allocate memory for the device
    internal_mem = 128*1024
    device_start = simstate.heap.malloc(internal_mem)
    simstate.memory.store(device_start, 
        simstate.solver.BVS("internal_mem", internal_mem*8),
        endness = mem_end)
    if device_start & 0b1111 != 0:
        raise Exception("TODO")
    simstate.globals['device_addr'] = device_start
    # Allocate memory for PCI
    pci_mem = 256
    pci_start = simstate.heap.malloc(pci_mem)
    simstate.memory.store(pci_start, 
        simstate.solver.BVS("pci_memory", pci_mem*8),
        endness = mem_end)
    if device_start & 0b11 != 0:
        raise Exception("TODO")
    simstate.globals['pci_address'] = pci_start

    # We can use initial values only after a global reset
    simstate.globals['use_init'] = False
    # Write device address to appropriate BARs:
    low = (device_start & 0xffffffff) | (0b0100)
    spec_reg.pci_regs['BAR0']['fields']['Low']['init'] = low
    high = device_start >> 32
    spec_reg.pci_regs['BAR1']['fields']['High']['init'] = high
    return simstate

def __get_sim_tn_net_device_ptr(base_state): 
    # Simple Caching
    if 'sim_device' in base_state.globals.keys():
        return base_state.globals['sim_device']
    device_struct_bytes = 8 + 1 + 7
    sim_tn_device = base_state.heap.malloc(device_struct_bytes)
    mem_end = base_state.arch.memory_endness
    base_state.memory.store(sim_tn_device, 
        base_state.solver.BVS("sim_tn_net_device", device_struct_bytes*8), 
        endness=mem_end)
    # Zero out rx_enabled field
    base_state.memory.store(sim_tn_device + 8, 
        base_state.solver.BVV(0, 8), 
        endness=mem_end)
    
    # Set device address
    dev_addr = base_state.globals['device_addr']
    base_state.memory.store(sim_tn_device, 
        base_state.solver.BVV(dev_addr, 64), 
        endness=mem_end)
    base_state.globals['sim_device'] = sim_tn_device
    return sim_tn_device

def get_promiscous_state(proj, base_state, concrete_device):
    function = proj.loader.find_symbol('tn_net_device_set_promiscuous') 
    device_ptr = concrete_device
    if concrete_device == None:
        device_ptr = __get_sim_tn_net_device_ptr(base_state)
    state = proj.factory.call_state(function.rebased_addr, 
        device_ptr, 
        add_options={angr.sim_options.TRACK_SOLVER_VARIABLES}, 
        base_state=base_state)
    return state

def __get_sim_tn_net_agent_ptr(base_state): 
    # Simple Caching
    if 'sim_agent' in base_state.globals.keys():
        return base_state.globals['sim_agent']
    agent_struct_bytes = 8*5 + 1*3*8 + 4*4*16 + 8*4 + 8*4
    sim_tn_agent = base_state.heap.malloc(agent_struct_bytes)
    mem_end = base_state.arch.memory_endness
    agent = base_state.solver.BVS("sim_tn_agent", agent_struct_bytes*8)
    base_state.memory.store(sim_tn_agent, 
        agent, 
        endness=mem_end)
    base_state.globals['sim_agent'] = sim_tn_agent
    return sim_tn_agent

def get_receive_init_state(proj, base_state, concrete_agent, concrete_device):
    function = proj.loader.find_symbol('tn_net_agent_set_input')
    agent_ptr = concrete_agent
    if concrete_agent == None:
        agent_ptr = __get_sim_tn_net_agent_ptr(base_state)
    device_ptr = concrete_device
    if concrete_device == None:
        device_ptr = __get_sim_tn_net_device_ptr(base_state)
    state = proj.factory.call_state(function.rebased_addr, 
        agent_ptr, device_ptr, 
        add_options={angr.sim_options.TRACK_SOLVER_VARIABLES}, 
        base_state=base_state)
    return state

def get_transmit_init_state(proj, base_state, concrete_agent, concrete_device):
    function = proj.loader.find_symbol('tn_net_agent_add_output')
    agent_ptr = concrete_agent
    if concrete_agent == None:
        agent_ptr = __get_sim_tn_net_agent_ptr(base_state)
    device_ptr = concrete_device
    if concrete_device == None:
        device_ptr = __get_sim_tn_net_device_ptr(base_state)
    state = proj.factory.call_state(function.rebased_addr, 
        agent_ptr, device_ptr, 
        add_options={angr.sim_options.TRACK_SOLVER_VARIABLES}, 
        base_state=base_state)
    return state

def get_con_tn_agent_ptr(proj, base_state):
    sim_tn_agent_ptr = base_state.heap.malloc(8)
    mem_end = base_state.arch.memory_endness
    base_state.memory.store(sim_tn_agent_ptr, 
        base_state.solver.BVS("agent_ptr", 8*8), endness=mem_end)
    function = proj.loader.find_symbol('tn_net_agent_init') 
    state = proj.factory.call_state(function.rebased_addr, 
        sim_tn_agent_ptr, 
        add_options={angr.sim_options.TRACK_SOLVER_VARIABLES}, 
        base_state=base_state)
    deadended = __run_symbex(proj, state, None)
    assert(len(deadended)==1)
    alloc_state = deadended[0]
    sim_tn_agent = alloc_state.memory.load(sim_tn_agent_ptr, 8, 
         endness=mem_end)
    return sim_tn_agent, alloc_state

def get_con_tn_net_device_ptr(proj, base_state):
    sim_tn_device_ptr = base_state.heap.malloc(8)
    mem_end = base_state.arch.memory_endness
    base_state.memory.store(sim_tn_device_ptr, 
        base_state.solver.BVS("device_ptr", 8*8), endness=mem_end)
    sim_tn_pci_address = base_state.globals['pci_address']
    function = proj.loader.find_symbol('tn_net_device_init') 
    state = proj.factory.call_state(function.rebased_addr, 
        sim_tn_pci_address, sim_tn_device_ptr, 
        add_options={angr.sim_options.TRACK_SOLVER_VARIABLES}, 
        base_state=base_state)
    deadended = __run_symbex(proj, state, spec_act.device_init)
    cc = proj.factory.cc()
    for s in deadended:
        ret = s.solver.eval(cc.get_return_val(s))
        if ret == 0b1:
            sim_tn_device = s.memory.load(sim_tn_device_ptr, 8, 
            endness=mem_end)
            return sim_tn_device, s
    raise Exception("No state returns a good value!")
