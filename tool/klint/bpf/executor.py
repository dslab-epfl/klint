import claripy

from kalm import executor as kalm_executor
from klint.bpf import analysis
from klint.bpf import detection
from klint.bpf import externals
from klint.bpf import packet
from klint import executor as klint_executor
from klint import statistics

def get_external(name):
    return getattr(externals, name)

def execute(code_path, calls_path, maps_path):
    with open(code_path, 'rb') as code_file:
        code = code_file.read()
    blank = kalm_executor.create_blank_state(code)
    for (addr, name, map) in analysis.get_maps(maps_path, blank.sizes.ptr):
        externals.map_init(blank, addr, map)
    function = 0 # since our code is a single function
    exts = {a: get_external(n) for (a, n) in analysis.get_calls(calls_path)}
    return klint_executor.find_fixedpoint_states([(blank, lambda st: kalm_executor.create_calling_state(st, function, [packet.create(st)], exts))])
