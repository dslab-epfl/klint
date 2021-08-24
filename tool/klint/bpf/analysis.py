import angr
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
import inspect # ouch
import logging
import struct

from klint.bpf.maps import BpfMapDef

# somewhat inspired by https://blog.xaviermaso.com/2021/02/25/Handle-function-calls-during-static-analysis-with-angr.html
class FunctionCollectingHandler(FunctionHandler):
  def __init__(self):
      self.funcs = set()
  def hook(self, rda):
      return self
  def handle_unknown_call(self, state, src_codeloc=None):
      self.funcs.add(inspect.currentframe().f_back.f_locals['func_addr_int']) # this is terrible...
      return True, state
  def handle_local_function(self, state, function_address, call_stack, maximum_local_call_depth, visited_blocks, dependency_graph, src_ins_addr=None, codeloc=None):
      return True, state, visited_blocks, dependency_graph

def get_externals_addresses(shellcode_path, arch='amd64'):
    # otherwise we get warnings we don't care about
    logging.getLogger('angr.analyses.reaching_definitions.engine_vex').setLevel('ERROR')
    logging.getLogger('angr.analyses.cfg.cfg_base').setLevel('ERROR')
    with open(shellcode_path, 'rb') as shellcode_file:
        shellcode = shellcode_file.read()
        proj = angr.load_shellcode(shellcode, arch)
        cfg = proj.analyses.CFG()
        handler = FunctionCollectingHandler()
        proj.analyses.ReachingDefinitions(function_handler=handler, observe_all=True, subject=cfg.functions[0])
        return handler.funcs

def get_externals_names(ops_path):
    with open(ops_path, 'r') as ops_file:
        ops = ops_file.readlines()
        # example line: '  46: (85) call __htab_map_lookup_elem#104256\n'
        return set([l.strip().split(' ')[3].split('#')[0] for l in ops if ' call ' in l])

def get_maps(maps_path):
    with open(maps_path, 'rb') as maps_file:
        maps = maps_file.read()
        chunks = [maps[i:i + 4] for i in range(0, len(maps), 4)]
        ints = [struct.unpack('i', c)[0] for c in chunks]
        map_defs = [ints[i:i + 5] for i in range(0, len(ints), 5)]
        if len(map_defs[-1]) != 5:
            raise Exception('Unexpected number of bytes in maps section...')
        return [BpfMapDef(d[0], d[1], d[2], d[3], d[4]) for d in map_defs]
