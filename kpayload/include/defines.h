/* golden */
/* 1/2/2018 */

#ifndef _DEFINES_H
#define _DEFINES_H

// all the defines needed for jkpayload fself and fpkg
// TODO: find a better way to incorporate these definitions into the code? (feels icky rn)

#include "jkpayload.h"

#define NULL 0
#define offsetof(st, m) ((size_t)((char *)&((st *)(0))->m - (char *)0))

// TODO: fix these hacks :/
#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

#endif
