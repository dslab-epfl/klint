#include "os/endian.h"

#include <stdint.h>


uint16_t rte_be_to_cpu_16(uint16_t x)
{
	return os_be_to_cpu16(x);
}

uint16_t rte_cpu_to_be_16(uint16_t x)
{
	return os_cpu_to_be16(x);
}
