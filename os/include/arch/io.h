#pragma once

#include <stdint.h>


static inline void io_port_out8(uint16_t port, uint8_t value)
{
	__asm__ volatile("outb %0, %1" : : "a"(value), "dN"(port));
}

static inline void io_port_out32(uint16_t port, uint32_t value)
{
	__asm__ volatile("outl %0, %1" : : "a"(value), "dN"(port));
}

static inline uint32_t io_port_in32(uint16_t port)
{
	uint32_t result;
	__asm__ volatile("inl %1, %0" : "=a"(result) : "dN"(port));
	return result;
}
