import angr
import executors.binary.clock as clock

class Time(angr.SimProcedure):
  def run(self):
    return clock.get_current_time(self.state)
