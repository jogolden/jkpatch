/* golden */
/* 1/2/2018 */

#ifndef _FPKG_H
#define _FPKG_H

#include "jkpayload.h"
#include "keys.h"
#include "proc.h"

#define MAX_FAKE_KEYS 32

struct fake_key_desc {
	uint8_t key[0x20];
	int occupied;
};

static const uint8_t s_fake_key_seed[0x10] = {
	0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45
};

extern struct fake_key_desc s_fake_keys[MAX_FAKE_KEYS];
extern struct sx s_fake_keys_lock;

int shellcore_fpkg_patch();
void install_fpkg_hooks();

#endif
