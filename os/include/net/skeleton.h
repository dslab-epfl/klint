#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "os/config.h"
#include "net/packet.h"
#include "net/tx.h" // transitive include as convenience for implementers


// Initialize any necessary state, given the number of devices; returns true iff initialization succeeded.
bool nf_init(device_t devices_count);
//@ requires devices_count > 0;
//@ ensures emp;

// Handles a packet
void nf_handle(struct net_packet* packet);
//@ requires *packet |-> _;
//@ ensures *packet |-> _;


// Convenience method
static inline device_t os_config_get_device(const char* name, device_t devices_count)
{
	return (device_t) os_config_try_get(name, 0, devices_count - 1);
}
