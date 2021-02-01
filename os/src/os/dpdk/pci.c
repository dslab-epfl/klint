#include "os/pci.h"

#include "os/fail.h"


size_t os_pci_enumerate(struct os_pci_address** out_devices)
{
	(void) out_devices;

	os_fail("os_pci_enumerate is not supported");
}

uint32_t os_pci_read(struct os_pci_address address, uint8_t reg)
{
	(void) address;
	(void) reg;

	os_fail("os_pci_read is not supported");
}

void os_pci_write(struct os_pci_address address, uint8_t reg, uint32_t value)
{
	(void) address;
	(void) reg;
	(void) value;

	os_fail("os_pci_write is not supported");
}
