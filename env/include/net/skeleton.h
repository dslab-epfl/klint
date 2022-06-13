#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "os/config.h"
#include "net/packet.h"
#include "net/tx.h" // transitive include as convenience for implementers

/**
 * @interface nf
 * @brief Network functions have two mandatory methods and can read from a file named @p config
 *
 * @details The config file must be in the format mentioned bellow \n
 * @p {"[key name]", [value: must be an integer]} \n
 * Multiple entries like the above can be added but must be separated by a @p comma
 *
 *
 *
 * @see nf_init()
 * @see nf_handle()
 */

/**
 * @brief Initialize any necessary state required by the nf.
 *
 * @attention This is where all the memory space required by the nf shall be granted
 *
 * @param devices_count number of device/interface required by the nf
 * @return true initialization successful
 * @return false initialization failed
 */
bool nf_init(device_t devices_count);
//@ requires devices_count > 0;
//@ ensures emp;

/**
 * @brief Performs the nf actions once packet are sent to the nf
 *
 * @attention In order to prevent faults, no memory allocation can be performed in this function
 *
 *
 * @param packet
 */
void nf_handle(struct net_packet *packet);
//@ requires *packet |-> _;
//@ ensures *packet |-> _;

// Convenience method
/**
 * @brief Read device from the config file
 *
 * @param name the name of the config file
 * @param devices_count number of device left to be read
 * @param out_value id of the device read
 * @return true device id was read successfully
 * @return false device id was not read successfully
 */
static inline bool os_config_get_device(const char *name, device_t devices_count, device_t *out_value)
{
	uint64_t value;
	if (!os_config_get(name, 0, devices_count - 1, &value))
	{ // the max param is inclusive
		return false;
	}
	*out_value = (device_t)value;
	return true;
}
