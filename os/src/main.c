#include "os/skeleton/nf.h"
#include "os/debug.h"

#include "clock_private.h"
#include "fail.h"
#include "network_private.h"

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#define INFINITE_LOOP                                     \
	int _loop_termination = klee_int("loop_termination"); \
	while (klee_induce_invariants() & _loop_termination)
#else
#define INFINITE_LOOP while (1)
#endif

int main(int argc, char **argv)
{
	// Initialize networking, change argc/argv so we're left with non-network stuff
	int ret = os_net_init(argc, argv);
	argc -= ret;
	argv += ret;

	uint16_t nb_devices = os_net_devices_count();
	if (!nf_init(nb_devices))
	{
		fail("Initialization failed.");
	}

	INFINITE_LOOP
	{
		os_clock_flush();
		for (uint16_t device = 0; device < nb_devices; device++)
		{
			struct os_net_packet *packet = os_net_receive(device);
			if (packet != NULL)
			{
				// os_debug("== PACKET ==");
				// os_debug("_reserved0: 0x%llx", packet->_reserved0);
				// os_debug("_reserved1: 0x%hx", packet->_reserved1);
				// os_debug("_reserved2: 0x%hx", packet->_reserved2);
				// os_debug("_reserved3: 0x%hx", packet->_reserved3);
				// os_debug("device: 0x%hx", packet->device);
				// os_debug("_reserved4: 0x%llx", packet->_reserved4);
				// os_debug("_reserved5: 0x%x", packet->_reserved5);
				// os_debug("_reserved6: 0x%x", packet->_reserved6);
				// os_debug("length: 0x%hx", packet->length);
				// os_debug("== ETHERNET HEADER ==");
				// os_debug("src_addr: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx ", packet->data[0], packet->data[1],
				// 		 packet->data[2], packet->data[3], packet->data[4], packet->data[5]);
				// os_debug("dst_addr: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx ", packet->data[6], packet->data[7],
				// 		 packet->data[8], packet->data[9], packet->data[10], packet->data[11]);
				// os_debug("ether_type: 0x%hx", packet->data[12]);
				// os_debug("== IPV4 HEADER ==");
				// os_debug("version_ihl: 0x%hhx", packet->data[14]);
				// os_debug("type_of_service: 0x%hhx", packet->data[15]);
				// os_debug("total_length: 0x%hx", packet->data[16]);
				// os_debug("packet_id: 0x%hx", packet->data[18]);
				// os_debug("fragment_offset: 0x%hx", packet->data[20]);
				// os_debug("time_to_live: 0x%hhx", packet->data[22]);
				// os_debug("next_proto_id: 0x%hhx", packet->data[23]);
				// os_debug("hdr_checksum: 0x%hx", packet->data[24]);
				// os_debug("src_addr: 0x%x", packet->data[26]);
				// os_debug("dst_addr: 0x%x", packet->data[30]);
				// os_debug("== TCP/UDP HEADER ==");
				// os_debug("src_port: 0x%hx", packet->data[34]);
				// os_debug("dst_port: 0x%hx", packet->data[36]);
				nf_handle(packet);
				os_net_cleanup(packet);
			}
		}
	}

	return 0;
}
