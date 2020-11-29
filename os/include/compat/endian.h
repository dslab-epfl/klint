#pragma once

// https://stackoverflow.com/a/4240257/3311770
#define IS_BIG_ENDIAN (!(((union { unsigned x; unsigned char c; }){1}).c))
