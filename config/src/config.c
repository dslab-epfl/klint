#include "config/config.h"

#include <stddef.h>
#include <string.h>


struct config_item
{
	const char* name;
	uintmax_t value;
};

struct config_item items[] =
{
#include CONFIG_FILENAME
};

bool config_get(const char* name, uintmax_t* out_value)
{
	for (size_t n = 0; n < sizeof(items)/sizeof(struct config_item); n++) {
		if (strcmp(items[n].name, name) == 0) {
			*out_value = items[n].value;
			return true;
		}
	}
	return false;
}
