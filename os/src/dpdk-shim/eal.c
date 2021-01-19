#include <rte_eal.h>

#include <stdbool.h>

static bool initialized;

int rte_eal_init(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	if (initialized) {
		return -1;
	}
	initialized = true;
	return 0;
}
