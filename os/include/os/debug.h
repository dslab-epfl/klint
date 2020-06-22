#pragma once

#ifdef DEBUG
void os_debug(const char* format, ...);
#else
#define os_debug(...)
#endif
