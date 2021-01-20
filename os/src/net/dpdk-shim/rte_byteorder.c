#include <rte_byteorder.h>

#include <stdint.h>

#include "arch/endian.h"


uint16_t rte_be_to_cpu_16(uint16_t x)
{
	return be_to_cpu16(x);
}

uint16_t rte_cpu_to_be_16(uint16_t x)
{
	return cpu_to_be16(x);
}

uint16_t rte_le_to_cpu_16(uint16_t x)
{
	return le_to_cpu16(x);
}

uint16_t rte_cpu_to_le_16(uint16_t x)
{
	return cpu_to_le16(x);
}

uint32_t rte_le_to_cpu_32(uint32_t x)
{
	return le_to_cpu32(x);
}

uint32_t rte_cpu_to_le_32(uint32_t x)
{
	return cpu_to_le32(x);
}

uint32_t rte_be_to_cpu_32(uint32_t x)
{
	return be_to_cpu32(x);
}

uint64_t rte_cpu_to_le_64(uint64_t x)
{
	return cpu_to_le64(x);
}
