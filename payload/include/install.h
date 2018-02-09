/* golden */
/* 1/2/2018 */

#ifndef _INSTALL_H
#define _INSTALL_H

#include "jkpatch.h"

int install_payload(struct thread *td, uint64_t kernbase, void *payload, size_t psize);

#endif
