#include "os/pci.h"

#include "os/error.h"


size_t os_pci_enumerate(struct os_pci_address** out_addresses)
{
	(void) out_addresses;

	os_fatal("os_pci_enumerate is not supported");
}

uint32_t os_pci_read(const struct os_pci_address* address, uint8_t reg)
{
	(void) address;
	(void) reg;

	os_fatal("os_pci_read is not supported");
}

void os_pci_write(const struct os_pci_address* address, uint8_t reg, uint32_t value)
{
	(void) address;
	(void) reg;
	(void) value;

	os_fatal("os_pci_write is not supported");
}
