#include "os/pci.h"

#include "arch/io.h"


// Physical addresses at which we can talk to PCI via geographical addressing
#define PCI_CONFIG_ADDR 0xCF8
#define PCI_CONFIG_DATA 0xCFC


static struct os_pci_address addresses[] =
{
#include OS_CONFIG_FILENAME
};


size_t os_pci_enumerate(struct os_pci_address** out_addresses)
{
	*out_addresses = addresses;
	return sizeof(addresses)/sizeof(struct os_pci_address);
}


static void pci_target(const struct os_pci_address address, const uint8_t reg)
{
	const uint32_t reg_addr = 0x80000000u | ((uint32_t) address.bus << 16) | ((uint32_t) address.device << 11) | ((uint32_t) address.function << 8) | reg;
	io_port_out32(PCI_CONFIG_ADDR, reg_addr);
	// Wait til the out32 is done
	io_port_out8(0x80, 0);
}

uint32_t os_pci_read(const struct os_pci_address address, const uint8_t reg)
{
	pci_target(address, reg);
	return io_port_in32(PCI_CONFIG_DATA);
}

void os_pci_write(const struct os_pci_address address, const uint8_t reg, const uint32_t value)
{
	pci_target(address, reg);
	io_port_out32(PCI_CONFIG_DATA, value);
}
