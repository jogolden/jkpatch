/* golden */
/* 1/2/2018 */

#include "jkpayload.h"

#include "rpc.h"
#include "fself.h"
#include "fpkg.h"

int payload_entry(void *arg) {
	// initialize uart
	init_uart();

	// initialize rpc
	init_rpc();

	// fake self binaries
	install_fself_hooks();

	// fake package containers
	install_fpkg_hooks();

	return 0;
}
