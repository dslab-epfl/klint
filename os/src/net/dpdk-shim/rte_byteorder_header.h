// See the Makefile for an explanation

#pragma once

#include <stdint.h>


uint16_t rte_be_to_cpu_16(uint16_t x);
uint16_t rte_cpu_to_be_16(uint16_t x);
uint16_t rte_le_to_cpu_16(uint16_t x);
uint16_t rte_cpu_to_le_16(uint16_t x);
uint32_t rte_le_to_cpu_32(uint32_t x);
uint32_t rte_cpu_to_le_32(uint32_t x);
uint32_t rte_be_to_cpu_32(uint32_t x);
uint64_t rte_cpu_to_le_64(uint64_t x);
