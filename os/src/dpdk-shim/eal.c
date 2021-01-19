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

int rte_eal_has_hugepages(void)
{
	// OS ASSUMPTION: Hugepages are used
	return 1;
}

enum rte_proc_type_t rte_eal_process_type(void)
{
	// OS ASSUMPTION: Single thread
	return RTE_PROC_PRIMARY;
}
