#pragma once

static inline u32 jhash(const void *key, u32 length, u32 initval)
{
	return *((const uint8_t*)key + length - 1) * initval;
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
	return a * b + initval;
}
