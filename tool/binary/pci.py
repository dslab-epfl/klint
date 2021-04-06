# Standard/External libraries
import claripy
from angr.state_plugins.plugin import SimStatePlugin

# Only supports port I/O to PCI devices (and enforces it)
class PciPlugin(SimStatePlugin):
    def __init__(self, address=None, flushed=False, handle_read=None, handle_write=None):
        SimStatePlugin.__init__(self)
        self._address = address
        self._flushed = flushed
        self._handle_read = handle_read
        self._handle_write = handle_write

    @SimStatePlugin.memo
    def copy(self, memo):
        return PciPlugin(self._address, self._flushed, self._handle_read, self._handle_write)

    def merge(self, others, merge_conditions, common_ancestor=None):
        if any(o._handle_read != self._handle_read or o._handle_write != self._handle_write for o in others):
            raise Exception("Cannot merge PciPlugin with different handlers")
        self._address = None
        self._flushed = False
        return True


    # handle_read is (state, (B, D, F, reg)) -> value
    # handle_write is (state, (B, D, F, reg), value) -> None
    def set_handlers(self, handle_read, handle_write):
        self._handle_read = handle_read
        self._handle_write = handle_write

    def handle_in(self, port, size):
        if port != 0xCFC:
            raise Exception("Unknown port to read from for port I/O")
        if not self._flushed:
            raise Exception("Attempt to read from PCI via I/O without having addressed and flushed first")

        return self._handle_read(self.state, self._address)

    def handle_out(self, port, data, size):
        if port == 0xCF8:
            self._address = self._parse_address(data)
            self._flushed = False
        elif port == 0x80:
            if self._address is not None:
                self._flushed = True
        elif port == 0xCFC:
            if not self._flushed:
                raise Exception("Attempt to write to PCI via port I/O without having addressed and flushed first")
            self._handle_write(self.state, self._address, data)
        else:
            raise Exception("Unknown port to write to for port I/O")


    def _parse_address(self, data):
        data = data ^ claripy.BVV(0x80000000, 32)
        bus = self.state.solver.simplify(data[23:16])
        device = self.state.solver.simplify(data[15:11])
        function = self.state.solver.simplify(data[10:8])
        register = self.state.solver.simplify(data[7:0])
        return (bus, device, function, register)