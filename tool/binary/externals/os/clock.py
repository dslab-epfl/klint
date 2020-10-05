# Standard/External libraries
import angr

# Us
from ... import clock

class Time(angr.SimProcedure):
  def run(self):
    return clock.get_current_time(self.state)
