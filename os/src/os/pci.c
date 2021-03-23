#include "os/pci.h"


static struct os_pci_address addresses[] =
{
#include OS_CONFIG_FILENAME
};


size_t os_pci_enumerate(struct os_pci_address** out_addresses)
{
	*out_addresses = addresses;
	return sizeof(addresses)/sizeof(struct os_pci_address);
}
