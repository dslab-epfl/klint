
/**
 * @brief Reads a String from the config file
 *
 * @todo define the maximum byte size of the out_value we can have
 * @pre out_value must have a size greater or equal to
 *
 * @param name
 * @param out_value
 * @return true
 * @return false
 */
bool os_config_try_get_bytes(const char* name, void* out_value, size_t size);