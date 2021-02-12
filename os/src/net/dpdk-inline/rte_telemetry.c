#include <rte_telemetry.h>

int rte_telemetry_register_cmd(const char* cmd, telemetry_cb fn, const char* help)
{
	(void) cmd;
	(void) fn;
	(void) help;

	return 0;
}
