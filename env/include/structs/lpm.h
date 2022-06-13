#include <stdbool.h>

/* Note that in this implementation the ownership of the key and value will not be transferred to the LPM, their respactive data will be copied
 * to a memory space owned by the lpm.
 */

struct lpm;

/**
 * @brief Create an longer prefix match data structure
 *
 * @param key_size The key size, in bytes
 * @param value_size The value size, in bytes
 * @param capacity The maximal capacity
 */
struct lpm* lpm_alloc(size_t key_size, size_t value_size, size_t capacity);

/**
 * @brief Set a key/width, value pair in the lpm
 *
 * @pre the key combined with the width must not already exist in the lpm
 * @pre the width cannot be greater than key_size * 8
 * @post the number of elements in the lpm must not exceed the lpm capacity.
 *
 * @return true set succeeded (= there was free space)
 * @return false set failed (= there was no free space)
 */
bool lpm_set(struct lpm* lpm, void* key, size_t width, void* value);

/**
 * @brief performs a longest prefix match search on the lpm.
 *
 * @pre value must point to a block of value_size bytes
 *
 * @return true entry found
 * @return false no entry found
 */
bool lpm_search(struct lpm* lpm, void* key, void* out_value);

/**
 * @brief Removes a key and its value from the lpm
 *
 * @pre the key and width combination must exist in the lpm
 * @pre the key width cannot be greater than key_size * 8
 */
void lpm_remove(struct lpm* lpm, void* key, size_t width);
