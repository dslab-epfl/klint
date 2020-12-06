# Standard/External libraries
import angr

# Us
from ... import cast
from ... import utils

class Debug(angr.SimProcedure):
    def run(self, text):
        text = cast.ptr(text)
        py_text = utils.read_str(self.state, text)
        print("DEBUG: " + py_text)
