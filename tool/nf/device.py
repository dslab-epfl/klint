from collections import namedtuple

SpecDevice = namedtuple('SpecDevice', ['phys_addr', 'virt_addr', 'pci_regs', 'regs'])