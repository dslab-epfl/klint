#include "os/skeleton/nf.h"

#include "clock_private.h"
#include "fail.h"
#include "network_private.h"

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#define INFINITE_LOOP int _loop_termination = klee_int("loop_termination"); while(klee_induce_invariants() & _loop_termination)
#else
#define INFINITE_LOOP while(1)
#endif


int main(int argc, char** argv)
{
	// Initialize networking, change argc/argv so we're left with non-network stuff
	int ret = os_net_init(argc, argv);
	argc -= ret;
	argv += ret;

	uint16_t nb_devices = os_net_devices_count();
	if (!nf_init(nb_devices)) {
		fail("Initialization failed.");
	}

	INFINITE_LOOP {
		os_clock_flush();
		for (uint16_t device = 0; device < nb_devices; device++) {
			struct os_net_packet* packet = os_net_receive(device);
			if (packet != NULL) {
				nf_handle(packet);
				os_net_cleanup(packet);
			}
		}
	}

	return 0;
}
