#include <rte_bus_pci.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ethdev_driver.h>
#include <rte_pci.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "os/fail.h"
#include "os/memory.h"
#include "os/pci.h"


// Can be anything; some drivers register multiple instances, e.g. PF+VF
#define MAX_DRIVERS 16


static struct rte_pci_driver* drivers[MAX_DRIVERS];
static size_t drivers_count;

static struct os_pci_address* pci_devices;
static struct rte_pci_device* rte_pci_devices;
static struct rte_device* devices;
struct rte_eth_dev rte_eth_devices[RTE_MAX_ETHPORTS];
static struct rte_eth_dev_data* rte_eth_devices_data;
static size_t devices_count;

static bool initialized;


// Called by driver constructors, to register themselves as PCI drivers
void rte_pci_register(struct rte_pci_driver* driver)
{
	drivers[drivers_count] = driver;
	drivers_count = drivers_count + 1;
}

// Called by drivers probe, to initialize the driver itself
int rte_eth_dev_create(struct rte_device* device, const char* name, size_t priv_data_size, ethdev_bus_specific_init bus_specific_init, void* bus_init_params, ethdev_init_t ethdev_init, void* init_params)
{
	// At this point, devices_count has the value of the next index to use
	struct rte_eth_dev* dev = &(rte_eth_devices[devices_count]);

	dev->device = device;
	dev->data = &(rte_eth_devices_data[devices_count]);
	dev->data->dev_private = os_memory_alloc(1, priv_data_size);
	// Ignore dev->data->name...
	dev->data->port_id = devices_count;
	dev->data->mtu = RTE_ETHER_MTU;

	int bus_result = bus_specific_init(dev, bus_init_params);
	if (bus_result < 0) {
		return bus_result;
	}

	int dev_result = ethdev_init(dev, init_params);
	if (dev_result < 0) {
		return dev_result;
	}

	return 0;
}

// Called by NF init to initialize DPDK
int rte_eal_init(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	if (initialized) {
		return -1;
	}

	// Do not set devices_count directly; the callbacks used during probe must know which index to use
	size_t total_devices_count = os_pci_enumerate(&pci_devices);
	if (total_devices_count > RTE_MAX_ETHPORTS) {
		os_fail("Too many devices");
	}

	rte_pci_devices = os_memory_alloc(total_devices_count, sizeof(struct rte_pci_device));
	devices = os_memory_alloc(total_devices_count, sizeof(struct rte_device));
	rte_eth_devices_data = os_memory_alloc(total_devices_count, sizeof(struct rte_eth_dev_data));

	for (size_t dev = 0; dev < total_devices_count; dev++) {
		uint32_t dev_and_vendor = os_pci_read(pci_devices[dev], 0x00);
		uint16_t device_id = dev_and_vendor >> 16;
		uint16_t vendor_id = dev_and_vendor & 0xFFFF;

		uint32_t class_id = os_pci_read(pci_devices[dev], 0x08) >> 8;

		uint32_t subsys_and_vendor = os_pci_read(pci_devices[dev], 0x2C);
		uint16_t subsystem_id = subsys_and_vendor >> 16;
		uint16_t subsystem_vendor_id = subsys_and_vendor & 0xFFFF;

		rte_pci_devices[dev].id.device_id = device_id;
		rte_pci_devices[dev].id.vendor_id = vendor_id;
		rte_pci_devices[dev].id.class_id = class_id;
		rte_pci_devices[dev].id.subsystem_device_id = subsystem_id;
		rte_pci_devices[dev].id.subsystem_vendor_id = subsystem_vendor_id;

		bool found = false;
		for (size_t dri = 0; dri < drivers_count; dri++) {
			for (const struct rte_pci_id* id = drivers[dri]->id_table; id->vendor_id != 0; id++) {
				if (device_id != id->device_id && id->device_id != PCI_ANY_ID) {
					continue;
				}
				if (vendor_id != id->vendor_id && id->vendor_id != PCI_ANY_ID) {
					continue;
				}
				if (class_id != id->class_id && id->class_id != RTE_CLASS_ANY_ID) {
					continue;
				}
				if (subsystem_id != id->subsystem_device_id && id->subsystem_device_id != PCI_ANY_ID) {
					continue;
				}
				if (subsystem_vendor_id != id->subsystem_vendor_id && id->subsystem_vendor_id != PCI_ANY_ID) {
					continue;
				}

				found = true;
				break;
			}

			if (!found) {
				continue;
			}

			rte_pci_devices[dev].driver = drivers[dri];

			if ((drivers[dri]->drv_flags & RTE_PCI_DRV_NEED_MAPPING) != 0) {
				// For now let's only support devices that need a single 64-bit memory BAR
				_Static_assert(sizeof(uintptr_t) >= sizeof(uint64_t), "Pointers need to be at least 64-bit for this code to work");
				uint32_t bar0_low = os_pci_read(pci_devices[dev], 0x10);
				uint32_t bar0_high = os_pci_read(pci_devices[dev], 0x14);

				// Memory is indicated by bit 0 being 0
				if ((bar0_low & 1) != 0) {
					os_fail("Unexpected BAR: not memory");
				}

				// 64-bit is indicated by bits 2:1 being 10
				if (((bar0_low >> 1) & 2) == 0) {
					os_fail("Unexpected BAR: not 64-it");
				}

				// Note that bit 3 of memory BARs indicates prefetchability; we don't care

				// Get the size by writing all-1s and reading what is actually written; the address is always aligned to the size
				os_pci_write(pci_devices[dev], 0x10, (uint32_t) -1);
				uint32_t read_val = os_pci_read(pci_devices[dev], 0x10);

				// Immediately restore the old value, if we crash inbetween write the machine will be in a weird state
				os_pci_write(pci_devices[dev], 0x10, bar0_low);

				if ((read_val >> 4) == 0) {
					os_fail("Unexpected BAR: size too big");
				}

				uint32_t bar_size = ~(read_val & ~0xF) + 1;
				uintptr_t bar_phys_addr = ((uintptr_t) bar0_high << 32) | ((uintptr_t) bar0_low & ~0xF);
				void* bar_virt_addr = os_memory_phys_to_virt(bar_phys_addr, bar_size);

				rte_pci_devices[dev].mem_resource[0].phys_addr = bar_phys_addr;
				rte_pci_devices[dev].mem_resource[0].addr = bar_virt_addr;
				rte_pci_devices[dev].mem_resource[0].len = bar_size;
			}

			rte_pci_devices[dev].device = devices[dev];

			int probe_result = drivers[dri]->probe(drivers[dri], &(rte_pci_devices[dev]));
			if (probe_result < 0) {
				os_fail("Probe failed");
			}

			break; // we found a driver, don't keep trying
		}

		if (!found) {
			os_fail("Could not find a driver");
		}

		devices_count = devices_count + 1;
	}

	initialized = true;
	return 0;
}

uint16_t rte_eth_dev_count_avail(void)
{
	return devices_count;
}

enum rte_proc_type_t rte_eal_process_type(void)
{
	// OS ASSUMPTION: Single core
	return RTE_PROC_PRIMARY;
}
