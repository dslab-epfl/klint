#include "os/config.h"


struct config_item
{
	const char* name;
	uintmax_t value;
};

static struct config_item items[] =
{
#include NF_CONFIG_FILENAME
};

bool os_config_get(const char* name, uintmax_t* out_value)
{
	for (size_t n = 0; n < sizeof(items)/sizeof(struct config_item); n++) {
		size_t c = 0;
		for (; items[n].name[c] != '\0' && name[c] != '\0'; c++) {
			if (items[n].name[c] != name[c]) {
				break;
			}
		}
		if (items[n].name[c] == name[c]) { // meaning they're both \0
			*out_value = items[n].value;
			return true;
		}
	}
	return false;
}
