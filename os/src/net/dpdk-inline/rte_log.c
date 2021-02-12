#include <rte_log.h>


int rte_log_register_type_and_pick_level(const char* name, uint32_t level_def)
{
	(void) name;
	// level_def is the user-provided fallback if the name is unknown
	return level_def;
}

int rte_log(uint32_t level, uint32_t logtype, const char* format, ...)
{
	(void) level;
	(void) logtype;
	(void) format;
	return 0;
}
