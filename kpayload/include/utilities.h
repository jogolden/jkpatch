/* golden */
/* 1/2/2018 */

#ifndef _UTILITIES_H
#define _UTILITIES_H

#include "jkpayload.h"

// 0xE8 CALL rel16/32 Call Procedure
#define KCALL_REL32(k, src, dest) do { *(uint8_t *)(k + src) = 0xE8; *(uint32_t *)(k + src + 1) = ((dest - src) - 5); } while(0);
#define CALL_REL32(src, dest) do { *(uint8_t *)src = 0xE8; *(uint32_t *)(src + 1) = ((dest - src) - 5); } while(0);

uint64_t getkernbase();
void *alloc(uint32_t size);
void dealloc(void *addr);
void write_jmp(uint64_t address, uint64_t destination);

// used both by fself and fpkg
const struct sbl_map_list_entry *sceSblDriverFindMappedPageListByGpuVa(vm_offset_t gpu_va);
vm_offset_t sceSblDriverGpuVaToCpuVa(vm_offset_t gpu_va, size_t *num_page_groups);
struct sbl_key_rbtree_entry *sceSblKeymgrGetKey(unsigned int handle);

#endif
