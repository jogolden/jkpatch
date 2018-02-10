/* golden */
/* 1/2/2018 */

#include "jkpayload.h"

#include "rpc.h"
#include "fself.h"
#include "fpkg.h"

void hook_trap_fatal(uint64_t frame) {
	// todo: add more debug information
	kern_reboot(0);
}

void install_trap_hook() {
	// disable write protect
	uint64_t CR0 = __readcr0();
	__writecr0(CR0 & ~CR0_WP);

	uint64_t kernbase = getkernbase();

	memcpy((void *)(kernbase + 0xECA92), "\x4C\x89\xE7", 3); // mov rdi, r12
	write_jmp(kernbase + 0xECA95, (uint64_t)hook_trap_fatal);

	// restore CR0
	__writecr0(CR0);
}

int payload_entry(void *arg) {
	// initialize uart
	init_uart();

	// initialize rpc
	init_rpc();

	// fake self binaries
	install_fself_hooks();

	// fake package containers
	shellcore_fpkg_patch();
	install_fpkg_hooks();

	// install trap hook
	install_trap_hook();

	return 0;
}
