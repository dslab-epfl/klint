#pragma once

// TODO: Add debug levels (and fix commented-out "verbose" prints in tinynf's ixgbe)
// TODO: Turn os_fail into os_log_fatal or something... i.e. the debug level that can't be turned off

#ifdef DEBUG_LEVEL
void os_debug(const char* format, ...);
#else
static inline void os_debug(const char* format, ...)
{
	(void) format;
	// Nothing.
}
#endif
