#pragma once

#include <stddef.h>
#include <stdint.h>

// TODO can we intercept PCI reads/writes directly at the IO port level during verif? if so, could make os_pci_read/write part of arch/ instead

struct os_pci_address {
	uint8_t bus;
	uint8_t device;
	uint8_t function;
	uint8_t _padding[5];
};


// Returns the number of devices
size_t os_pci_enumerate(struct os_pci_address** out_addresses);

// Reads the given register of the device at the given address and return its value.
uint32_t os_pci_read(const struct os_pci_address* address, uint8_t reg);

// Writes the given value to the given register of the device at the given address
void os_pci_write(const struct os_pci_address* address, uint8_t reg, uint32_t value);
