import angr

class Abort(angr.SimProcedure):
    NO_RET = True
    def run(self):
        raise Exception('Unimplemented function')

# Instantiate this and call install() on it to make angr's externals management sound (i.e., any external call will error, not silently be symbolic)
class EmptyLibrary:
    def install(self):
        # remove everything else
        angr.SIM_LIBRARIES.clear()
        angr.SIM_PROCEDURES.clear()
        # set ourselves as a library
        angr.SIM_LIBRARIES['externals'] = self
        # angr hardcodes some stubs
        angr.SIM_PROCEDURES['stubs'] = {
            'ReturnUnconstrained': Abort,
            'CallReturn': angr.procedures.stubs.CallReturn.CallReturn, # to make call_state work
            'UnresolvableCallTarget': Abort,
            'UnresolvableJumpTarget': Abort,
            'PathTerminator': angr.procedures.stubs.PathTerminator.PathTerminator # this is a real one
        }

    def get(self, name, arch):
        return Abort

    # immutable; this makes things simpler
    def copy(self): return self