#pragma once

#include <stdint.h>


struct os_pci_address {
	uint8_t bus;
	uint8_t device;
	uint8_t function;
	uint8_t _padding[5];
};


// Returns the number of devices
size_t os_pci_enumerate(struct os_pci_address** out_devices);

// Reads the given register of the device at the given address and return its value.
//uint32_t os_pci_read(struct os_pci_address address, uint8_t reg);

// Writes the given value to the given register of the device at the given address
//void os_pci_write(struct os_pci_address address, uint8_t reg, uint32_t value);
