import angr
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
import inspect # ouch

# somewhat inspired by https://blog.xaviermaso.com/2021/02/25/Handle-function-calls-during-static-analysis-with-angr.html
class FunctionCollectingHandler(FunctionHandler):
  def __init__(self):
      self.funcs = set()
  def hook(self, rda):
      return self
  def handle_unknown_call(self, state, src_codeloc=None):
      self.funcs.add(inspect.currentframe().f_back.f_locals['func_addr_int']) # this is terrible...
      return True, args[0]
  def handle_local_function(self, state, function_address, call_stack, maximum_local_call_depth, visited_blocks, dependency_graph, src_ins_addr=None, codeloc=None):
      return True, state, visited_blocks, dependency_graph

def find_externals_addresses(shellcode, arch='amd64'):
    proj = angr.load_shellcode(shellcode, arch)
    handler = FunctionCollectingHandler()
    p.analyses.ReachingDefinitions(function_handler=handler, observe_all=True, subject=p.kb.functions[0])
    return handler.funcs
