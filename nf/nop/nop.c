#include "net/skeleton.h"


device_t wan_device;
device_t lan_device;


bool nf_init(device_t devices_count)
{
	wan_device = os_config_get_device("wan device", devices_count);
	lan_device = os_config_get_device("lan device", devices_count);
	return lan_device != wan_device;
}


void nf_handle(struct net_packet* packet)
{
	device_t dst_device = packet->device == wan_device ? lan_device : wan_device;
	net_transmit(packet, dst_device, UPDATE_ETHER_ADDRS);
}
