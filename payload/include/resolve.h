/* golden */
/* 1/2/2018 */

#ifndef _RESOLVE_H
#define _RESOLVE_H

#include "jkpatch.h"

// data
void *M_TEMP;

/** functions **/
// freebsd/common
int (*printf)(const char *fmt, ...);
void *(*k_malloc)(unsigned long size, void *type, int flags);
void (*k_free)(void *addr, void *type);
void (*k_memcpy)(void *dst, const void *src, size_t len);
void *(*k_memset)(void * ptr, int value, size_t num);
int (*k_memcmp)(const void * ptr1, const void * ptr2, size_t num);
size_t (*k_strlen)(const char *str);

void resolve(uint64_t kernbase);

#endif
