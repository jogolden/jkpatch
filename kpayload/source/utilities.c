/* golden */
/* 1/2/2018 */

#include "utilities.h"

inline uint64_t getkernbase() {
	return __readmsr(0xC0000082) - __Xfast_syscall; // LSTAR syscall rip
}

inline void *alloc(uint32_t size) {
	return malloc(size, M_TEMP, 2);
}

inline void dealloc(void *addr) {
	free(addr, M_TEMP);
}

inline void write_jmp(uint64_t address, uint64_t destination) {
	// absolute jump
	*(uint8_t *)(address) = 0xFF;
	*(uint8_t *)(address + 1) = 0x25;
	*(uint8_t *)(address + 2) = 0x00;
	*(uint8_t *)(address + 3) = 0x00;
	*(uint8_t *)(address + 4) = 0x00;
	*(uint8_t *)(address + 5) = 0x00;
	*(uint64_t *)(address + 6) = destination;
}

const struct sbl_map_list_entry *sceSblDriverFindMappedPageListByGpuVa(vm_offset_t gpu_va) {
	const struct sbl_map_list_entry *entry;

	if (!gpu_va) {
		return NULL;
	}

	entry = *sbl_driver_mapped_pages;
	while (entry) {
		if (entry->gpu_va == gpu_va) {
			return entry;
		}

		entry = entry->next;
	}

	return NULL;
}

vm_offset_t sceSblDriverGpuVaToCpuVa(vm_offset_t gpu_va, size_t *num_page_groups) {
	const struct sbl_map_list_entry *entry = sceSblDriverFindMappedPageListByGpuVa(gpu_va);
	if (!entry) {
		return 0;
	}

	if (num_page_groups) {
		*num_page_groups = entry->num_page_groups;
	}

	return entry->cpu_va;
}

struct sbl_key_rbtree_entry *sceSblKeymgrGetKey(unsigned int handle) {
	struct sbl_key_rbtree_entry *entry = *sbl_keymgr_key_rbtree;

	while (entry) {
		if (entry->handle < handle) {
			entry = entry->right;
		} else if (entry->handle > handle)
			entry = entry->left;
		else if (entry->handle == handle) {
			return entry;
		}
	}

	return NULL;
}
