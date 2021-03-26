#include "os/pci.h"

#include <sys/io.h>

#include "os/log.h"


// Note that Linux requires programs to call `ioperm` before accessing ports.
__attribute__((constructor))
static void ensure_ioport_access(void)
{
	// Make sure we can talk to the devices
	// We access port 0x80 to wait after an outl, since it's the POST port so safe to do anything with (it's what glibc uses in the _p versions of outl/inl)
	// Also note that since reading an int32 is 4 bytes, we need to access 4 consecutive ports for PCI config/data.
	if (ioperm(0x80, 1, 1) < 0 || ioperm(PCI_CONFIG_ADDR, 4, 1) < 0 || ioperm(PCI_CONFIG_DATA, 4, 1) < 0) {
		os_fatal("PCI ioperms failed");
	}
}
