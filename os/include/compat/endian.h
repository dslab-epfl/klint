#pragma once

// https://stackoverflow.com/a/2100549/3311770
#define IS_BIG_ENDIAN (!*(unsigned char *)&(uint16_t){1})
