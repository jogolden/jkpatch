/* golden */
/* 1/2/2018 */

#ifndef _UTILITIES_H
#define _UTILITIES_H

#include "jkpatch.h"

// 0xE8 CALL rel16/32 Call Procedure
#define KCALL_REL32(k, src, dest) do { *(uint8_t *)(k + src) = 0xE8; *(uint32_t *)(k + src + 1) = ((dest - src) - 5); } while(0);
#define CALL_REL32(src, dest) do { *(uint8_t *)src = 0xE8; *(uint32_t *)(src + 1) = ((dest - src) - 5); } while(0);

uint64_t getkernbase();
void *alloc(uint32_t size);
void dealloc(void *addr);
void write_jmp(uint64_t address, uint64_t destination);

#endif
