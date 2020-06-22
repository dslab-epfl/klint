import angr
import executors.binary.cast as cast
import executors.binary.utils as utils

class Debug(angr.SimProcedure):
  def run(self, text):
    text = cast.ptr(text)
    py_text = utils.read_str(self.state, text)
    print("DEBUG: " + py_text)
