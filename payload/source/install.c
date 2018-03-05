/* golden */
/* 1/2/2018 */

#include "install.h"
#include "elf.h"

int install_payload(struct thread *td, uint64_t kernbase, void *payload, size_t psize) {
	vm_offset_t (*kmem_alloc)(vm_map_t map, vm_size_t size) = (void *)(kernbase + __kmem_alloc);
	vm_map_t kernel_map = *(vm_map_t *)(kernbase + __kernel_map);

	size_t msize = 0;
	if (elf_mapped_size(payload, &msize)) {
		printf("[jkpatch] install_payload: elf_mapped_size failed!\n");
		return 1;
	}

	int s = (msize + 0x3FFFull) & ~0x3FFFull;

	uint64_t CR0 = __readcr0();

	__writecr0(CR0 & ~CR0_WP);
	*(uint8_t *)(kernbase + 0x16ED8C) = 7; // VM_PROT_ALL;
	*(uint8_t *)(kernbase + 0x16EDA2) = 7; // VM_PROT_ALL;
	__writecr0(CR0);

	void *payloadbase = (void *)kmem_alloc(kernel_map, s);
	if (!payloadbase) {
		printf("[jkpatch] install_payload: kmem_alloc failed!\n");
		// need to set protection back to VM_PROT_DEFAULT...
		return 1;
	}

	__writecr0(CR0 & ~CR0_WP);
	*(uint8_t *)(kernbase + 0x16ED8C) = 3; // VM_PROT_DEFAULT;
	*(uint8_t *)(kernbase + 0x16EDA2) = 3; // VM_PROT_DEFAULT;
	__writecr0(CR0);

	// load the elf
	int r = 0;
	int (*payload_entry)(void *p);

	if ((r = load_elf(payload, psize, payloadbase, msize, (void **)&payload_entry))) {
		printf("[jkpatch] install_payload: load_elf failed (r: %i)!\n", r);
		return 1;
	}

	// call entry
	if (payload_entry(NULL)) {
		return 1;
	}

	printf("[jkpatch] payload loaded at 0x%llX\n", payloadbase);

	return 0;
}
