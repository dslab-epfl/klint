#ifndef VERIFAST_ONLY_NMMINTRIN_H_INCLUDED
#define VERIFAST_ONLY_NMMINTRIN_H_INCLUDED

// VeriFast doesn't know <nmmintrin.h> so we define it here
// The u64 definition looks odd but is correct!

#include <stdint.h>

uint32_t _mm_crc32_u8(uint32_t crc, uint8_t v);
//@ requires true;
//@ ensures true;

uint32_t _mm_crc32_u16(uint32_t crc, uint16_t v);
//@ requires true;
//@ ensures true;

uint32_t _mm_crc32_u32(uint32_t crc, uint32_t v);
//@ requires true;
//@ ensures true;

uint64_t _mm_crc32_u64(uint64_t crc, uint64_t v);
//@ requires true;
//@ ensures result <= UINT32_MAX;

#endif
