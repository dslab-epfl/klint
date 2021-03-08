#include "os/pci.h"

#include <sys/io.h>

#include "os/error.h"


// Physical addresses at which we can talk to PCI via geographical addressing
#define PCI_CONFIG_ADDR 0xCF8
#define PCI_CONFIG_DATA 0xCFC

static struct os_pci_address addresses[] =
{
#include OS_CONFIG_FILENAME
};


// Access PCI configuration space using port-mapped I/O: https://sysplay.github.io/books/LinuxDrivers/book/Content/Part08.html
// Note that Linux requires programs to call `ioperm` before accessing ports.
static void ensure_ioport_access(void)
{
	// Make sure we can talk to the devices
	// We access port 0x80 to wait after an outl, since it's the POST port so safe to do anything with (it's what glibc uses in the _p versions of outl/inl)
	// Also note that since reading an int32 is 4 bytes, we need to access 4 consecutive ports for PCI config/data.
	if (ioperm(0x80, 1, 1) < 0 || ioperm(PCI_CONFIG_ADDR, 4, 1) < 0 || ioperm(PCI_CONFIG_DATA, 4, 1) < 0) {
		os_fatal("PCI ioperms failed");
	}
}

static void pci_target(const struct os_pci_address address, const uint8_t reg)
{
	const uint32_t reg_addr = 0x80000000u | ((uint32_t) address.bus << 16) | ((uint32_t) address.device << 11) | ((uint32_t) address.function << 8) | reg;
	outl(reg_addr, PCI_CONFIG_ADDR);
	// Wait til the outl is done
	outb(0, 0x80);
}

size_t os_pci_enumerate(struct os_pci_address** out_addresses)
{
	*out_addresses = addresses;
	return sizeof(addresses)/sizeof(struct os_pci_address);
}

uint32_t os_pci_read(const struct os_pci_address address, const uint8_t reg)
{
	ensure_ioport_access();
	pci_target(address, reg);
	return inl(PCI_CONFIG_DATA);
}

void os_pci_write(const struct os_pci_address address, const uint8_t reg, const uint32_t value)
{
	ensure_ioport_access();
	pci_target(address, reg);
	outl(value, PCI_CONFIG_DATA);
}
