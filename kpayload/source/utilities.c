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
