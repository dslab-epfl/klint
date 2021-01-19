#pragma once

// returns the number of arguments consumed; aborts on failure
int os_net_init(int argc, char** argv);

uint16_t os_net_devices_count(void);

struct os_net_packet* os_net_receive(uint16_t device);

void os_net_cleanup(struct os_net_packet* packet);
