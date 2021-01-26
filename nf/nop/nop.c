#include "net/skeleton.h"

#include "os/config.h"


uint16_t wan_device;
uint16_t lan_device;

bool nf_init(uint16_t devices_count)
{
	wan_device = os_config_get_u16("wan device");
	lan_device = os_config_get_u16("lan device");
	return lan_device < devices_count && wan_device < devices_count && lan_device != wan_device;
}

void nf_handle(struct net_packet* packet)
{
	uint16_t dst_device = packet->device == wan_device ? lan_device : wan_device;
	net_transmit(packet, dst_device, UPDATE_ETHER_ADDRS);
}
