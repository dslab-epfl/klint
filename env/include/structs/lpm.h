#include <stdbool.h>

// NOTE: The LPM copies the keys and values it is given, ownership is not transferred.

struct lpm;

// Creates a longer prefix match data structure
//   key_size: The key size, in bytes
//   value_size: The value size, in bytes
//   capacity: The maximal capacity
struct lpm* lpm_alloc(size_t key_size, size_t value_size, size_t capacity);

// Sets a key/width, value pair in the lpm
// precondition: the key combined with the width must not already exist in the lpm
// precondition: the width cannot be greater than key_size * 8
// postcondition: the number of elements in the lpm cannot exceed the lpm capacity.
//   returns whether the set succeeded (= there was free space)
bool lpm_set(struct lpm* lpm, void* key, size_t width, void* value);

// Performs a longest prefix match search on the lpm.
// precondition: value must point to a block of value_size bytes
//   returns whether an entry was found
bool lpm_search(struct lpm* lpm, void* key, void* out_value);

// Removes a key and its value from the lpm if they exist
void lpm_remove(struct lpm* lpm, void* key, size_t width);
