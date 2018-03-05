/* golden */
/* 1/2/2018 */

#include "resolve.h"

void resolve(uint64_t kernbase) {
	M_TEMP = (void *)(kernbase + __M_TEMP);

#define r(name, offset) name = (void *)(kernbase + offset)
	r(printf, __printf);
	r(k_malloc, __malloc);
	r(k_free, __free);
	r(k_memcpy, __memcpy);
	r(k_memset, __memset);
	r(k_memcmp, __memcmp);
	r(k_strlen, __strlen);
}
