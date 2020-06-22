#pragma once

#include <stdlib.h>

#ifdef DEBUG
#include <stdio.h>
#define fail(...) do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); fflush(stderr); exit(1); } while(0)
#else
#define fail(...) exit(1)
#endif
