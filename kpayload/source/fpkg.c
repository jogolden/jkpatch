/* golden */
/* 1/2/2018 */

#include "fpkg.h"

#define MAX_FAKE_KEYS 32

struct fake_key_desc {
	uint8_t key[0x20];
	int occupied;
};

struct fake_key_desc s_fake_keys[MAX_FAKE_KEYS];
static struct sx s_fake_keys_lock;

const uint8_t s_fake_key_seed[0x10] = {
	0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45
};

struct fake_key_desc *get_free_fake_key_slot(void) {
	struct fake_key_desc *slot = NULL;
	size_t i;

	sx_xlock(&s_fake_keys_lock);
	{
		for (i = 0; i < COUNT_OF(s_fake_keys); ++i) {
			if (!s_fake_keys[i].occupied) {
				s_fake_keys[i].occupied = 1;
				slot = s_fake_keys + i;
				break;
			}
		}
	}
	sx_xunlock(&s_fake_keys_lock);

	return slot;
}

struct fake_key_desc *is_fake_pfs_key(uint8_t *key) {
	struct fake_key_desc* slot = NULL;
	size_t i;

	sx_xlock(&s_fake_keys_lock);
	{
		for (i = 0; i < COUNT_OF(s_fake_keys); ++i) {
			if (!s_fake_keys[i].occupied) {
				continue;
			}

			if (memcmp(s_fake_keys[i].key, key, sizeof(s_fake_keys[i].key)) == 0) {
				slot = s_fake_keys + i;
				break;
			}
		}
	}
	sx_xunlock(&s_fake_keys_lock);

	return slot;
}

/* a common function to generate a final key for PFS */
void pfs_gen_crypto_key(uint8_t *ekpfs, uint8_t seed[PFS_SEED_SIZE], unsigned int index, uint8_t key[PFS_FINAL_KEY_SIZE]) {
	struct thread *td = curthread();

	uint8_t d[4 + PFS_SEED_SIZE];
	memset(d, 0, sizeof(d));

	/* an index tells which key we should generate */
	memcpy(d, &index, 4); // ptr alias rules
	memcpy(d + 4, seed, PFS_SEED_SIZE);

	fpu_kern_enter(td, fpu_kern_ctx, 0);
	{
		Sha256Hmac(key, d, sizeof(d), ekpfs, EKPFS_SIZE);
	}
	fpu_kern_leave(td, fpu_kern_ctx);
}

/* an encryption key generator based on EKPFS and PFS header seed */
inline void pfs_generate_enc_key(uint8_t *ekpfs, uint8_t seed[PFS_SEED_SIZE], uint8_t key[PFS_FINAL_KEY_SIZE]) {
	pfs_gen_crypto_key(ekpfs, seed, 1, key);
}

/*  asigning key generator based on EKPFS and PFS header seed */
inline void pfs_generate_sign_key(uint8_t *ekpfs, uint8_t seed[PFS_SEED_SIZE], uint8_t key[PFS_FINAL_KEY_SIZE]) {
	pfs_gen_crypto_key(ekpfs, seed, 2, key);
}

int hook_sceSblPfsKeymgrIoctl__sceSblPfsKeymgrGenEKpfsForGDGPAC(pfs_key_blob_t *blob) {
	struct thread *td = curthread();
	struct rsa_buffer in_data;
	struct rsa_buffer out_data;
	struct rsa_key key;
	uint8_t dec_data[EEKPFS_SIZE];
	struct fake_key_desc *fake_key_slot;
	int ret;

	/* try to decrypt EEKPFS normally */
	ret = sceSblPfsKeymgrGenEKpfsForGDGPAC(blob);

	if (ret) {
		/* if this key is for debug/fake content, we could try to decrypt it manually */
		if (!blob->finalized) {
			memset(&in_data, 0, sizeof(in_data));
			{
				in_data.ptr = blob->eekpfs;
				in_data.size = sizeof(blob->eekpfs);
			}

			memset(&out_data, 0, sizeof(out_data));
			{
				out_data.ptr = dec_data;
				out_data.size = sizeof(dec_data);
			}

			memset(&key, 0, sizeof(key));
			{
				/* here we feed a custom key to the algorithm */
				key.p = (uint8_t *)s_ypkg_p;
				key.q = (uint8_t *)s_ypkg_q;
				key.dmp1 = (uint8_t *)s_ypkg_dmp1;
				key.dmq1 = (uint8_t *)s_ypkg_dmq1;
				key.iqmp = (uint8_t *)s_ypkg_iqmp;
			}

			fpu_kern_enter(td, fpu_kern_ctx, 0);
			{
				/* RSA PKCS1v15 */
				ret = RsaesPkcs1v15Dec2048CRT(&out_data, &in_data, &key);
			}
			fpu_kern_leave(td, fpu_kern_ctx);

			if (ret == 0) { /* got EKPFS key? */
				memcpy(blob->ekpfs, dec_data, sizeof(blob->ekpfs));

				/* add it to our key list */
				fake_key_slot = get_free_fake_key_slot();
				if (fake_key_slot) {
					memcpy(fake_key_slot->key, blob->ekpfs, sizeof(fake_key_slot->key));
				}
			}
		}
	}

	return ret;
}

int hook_pfs_sbl_init__sceSblPfsSetKey(unsigned int *ekh, unsigned int *skh, uint8_t *key, uint8_t *iv, int mode, int unused, uint8_t disc_flag) {
	struct sbl_key_rbtree_entry *key_entry;
	int is_fake_key;
	int ret;

	ret = sceSblPfsSetKey(ekh, skh, key, iv, mode, unused, disc_flag);

	/* check if it's a key that we have decrypted manually */
	is_fake_key = is_fake_pfs_key(key) != NULL;

	key_entry = sceSblKeymgrGetKey(*ekh); /* find a corresponding key entry */
	if (key_entry) {
		if (is_fake_key) {
			/* generate an encryption key */
			pfs_generate_enc_key(key, iv, key_entry->desc.pfs.key);
			memcpy(key_entry->desc.pfs.seed, s_fake_key_seed, sizeof(s_fake_key_seed));
		}
	}

	key_entry = sceSblKeymgrGetKey(*skh); /* find a corresponding key entry */
	if (key_entry) {
		if (is_fake_key) {
			/* generate a signing key */
			pfs_generate_sign_key(key, iv, key_entry->desc.pfs.key);
			memcpy(key_entry->desc.pfs.seed, s_fake_key_seed, sizeof(s_fake_key_seed));
		}
	}

	return ret;
}

int npdrm_decrypt_debug_rif(unsigned int type, uint8_t *data) {
	struct thread *td = curthread();
	int ret;

	fpu_kern_enter(td, fpu_kern_ctx, 0);
	{
		/* decrypt fake rif manually using a key from publishing tools */
		ret = AesCbcCfb128Decrypt(data + RIF_DIGEST_SIZE, data + RIF_DIGEST_SIZE, RIF_DATA_SIZE, rif_debug_key, sizeof(rif_debug_key) * 8, data);
		if (ret) {
			ret = 0x800F0A25; // SCE_SBL_ERROR_NPDRM_ENOTSUP
		}
	}
	fpu_kern_leave(td, fpu_kern_ctx);

	return ret;
}

int hook_npdrm_decrypt_isolated_rif__sceSblKeymgrSmCallfunc(union keymgr_payload *payload) {
	/* it's SM request, thus we have the GPU address here, so we need to convert it to the CPU address */
	union keymgr_request *request = (union keymgr_request *)sceSblDriverGpuVaToCpuVa(payload->data, NULL);
	int ret;

	/* try to decrypt rif normally */
	ret = sceSblKeymgrSmCallfunc(payload);

	// 0xFFFFFFFF832D0000

	/* and if it fails then we check if it's fake rif and try to decrypt it by ourselves */
	if ((ret != 0 || payload->status != 0) && request) {
		if (request->decrypt_rif.type == 0x200) { /* fake? */
			ret = npdrm_decrypt_debug_rif(request->decrypt_rif.type, request->decrypt_rif.data);
			payload->status = ret;
			ret = 0;
		}
	}

	return ret;
}

int hook_npdrm_decrypt_new_rif__sceSblKeymgrSmCallfunc(union keymgr_payload *payload) {
	/* it's SM request, thus we have the GPU address here, so we need to convert it to the CPU address */
	union keymgr_request *request = (union keymgr_request *)sceSblDriverGpuVaToCpuVa(payload->data, NULL);
	union keymgr_response *response = (union keymgr_response *)request;
	int ret, o, l;

	/* try to decrypt rif normally */
	ret = o = sceSblKeymgrSmCallfunc(payload);

	/* and if it fails then we check if it's fake rif and try to decrypt it by ourselves */
	if ((ret != 0 || payload->status != 0) && request) {
		if (request->decrypt_entire_rif.rif.format != 2) { /* not fake? */
			return o;
		}

		ret = npdrm_decrypt_debug_rif(request->decrypt_entire_rif.rif.format, request->decrypt_entire_rif.rif.digest);
		if (ret) {
			return o;
		}

		l = sizeof(request->decrypt_entire_rif.rif.digest) + sizeof(request->decrypt_entire_rif.rif.data);
		memcpy(response->decrypt_entire_rif.raw, request->decrypt_entire_rif.rif.digest, l);

		o = sizeof(request->decrypt_entire_rif.rif.digest) + sizeof(request->decrypt_entire_rif.rif.data);
		l = sizeof(response->decrypt_entire_rif.raw) - (sizeof(request->decrypt_entire_rif.rif.digest) + sizeof(request->decrypt_entire_rif.rif.data));
		memset(response->decrypt_entire_rif.raw + o, NULL, l);

		payload->status = ret;
		ret = 0;
	}

	return ret;
}

int ccp_msg_populate_key(unsigned int key_handle, uint8_t *key, int reverse) {
	struct sbl_key_rbtree_entry *key_entry;
	uint8_t *in_key;
	int i;
	int status = 0;

	/* searching for a key entry */
	key_entry = sceSblKeymgrGetKey(key_handle);

	if (key_entry) {
		/* we have found one, now checking if it's our key */
		if (memcmp(key_entry->desc.pfs.seed, s_fake_key_seed, sizeof(key_entry->desc.pfs.seed)) == 0) {
			/* currently we have a crypto request that use a key slot which should be already in CCP, but because we
			   did everything manually, we don't have this key slot, so we need to remove using of key slot and place
			   a plain key here */
			in_key = key_entry->desc.pfs.key;
			if (reverse) {
				/* reverse bytes of a key if it's needed */
				for (i = 0; i < 0x20; ++i) {
					key[0x20 - i - 1] = in_key[i];
				}
			} else {
				/* copy a key as is */
				memcpy(key, in_key, 0x20);
			}

			status = 1;
		}
	}

	return status;
}

int ccp_msg_populate_key_if_needed(struct ccp_msg *msg) {
	unsigned int cmd = msg->op.common.cmd;
	unsigned int type = CCP_OP(cmd);
	uint8_t *buf;
	int status = 0;

	/* skip messages that use plain keys and key slots */
	if (!(cmd & CCP_USE_KEY_HANDLE)) {
		goto skip;
	}

	buf = (uint8_t *)&msg->op;

	/* we only need to handle xts/hmac crypto operations */
	switch (type) {
	case CCP_OP_XTS:
		status = ccp_msg_populate_key(*(uint32_t *)(buf + 0x28), buf + 0x28, 1); /* xts key have a reversed byte order */
		break;
	case CCP_OP_HMAC:
		status = ccp_msg_populate_key(*(uint32_t *)(buf + 0x40), buf + 0x40, 0); /* hmac key have a normal byte order */
		break;
	default:
		goto skip;
	}

	/* if key was successfully populated, then remove the flag which tells CCP to use a key slot */
	if (status) {
		msg->op.common.cmd &= ~CCP_USE_KEY_HANDLE;
	}

skip:
	return status;
}

int hook_pfs_crypto__sceSblServiceCryptAsync(struct ccp_req *request) {
	struct ccp_msg *msg;
	int ret;

	TAILQ_FOREACH(msg, &request->msgs, next) {
		/* handle each message in crypto request */
		ccp_msg_populate_key_if_needed(msg);
	}

	/* run a crypto function normally */
	ret = sceSblServiceCryptAsync(request);

	return ret;
}

void install_fpkg_hooks() {
	// disable write protect
	uint64_t CR0 = __readcr0();
	__writecr0(CR0 & ~CR0_WP);

	uint64_t kernbase = getkernbase();

	sx_init_flags(&s_fake_keys_lock, "fake_keys_lock", 0);
	memset(s_fake_keys, 0, sizeof(s_fake_keys));

	write_jmp(kernbase + 0x61FF61, (uint64_t)hook_npdrm_decrypt_isolated_rif__sceSblKeymgrSmCallfunc);
	KCALL_REL32(kernbase, 0x61FDB0, 0x61FF61);

	write_jmp(kernbase + 0x6A4EB0, (uint64_t)hook_npdrm_decrypt_new_rif__sceSblKeymgrSmCallfunc);
	KCALL_REL32(kernbase, 0x6202FF, 0x6A4EB0);

	write_jmp(kernbase + 0x601051, (uint64_t)hook_sceSblPfsKeymgrIoctl__sceSblPfsKeymgrGenEKpfsForGDGPAC);
	KCALL_REL32(kernbase, 0x600885, 0x601051);
	KCALL_REL32(kernbase, 0x600921, 0x601051);

	write_jmp(kernbase + 0x68DE61, (uint64_t)hook_pfs_sbl_init__sceSblPfsSetKey);
	KCALL_REL32(kernbase, 0x68D078, 0x68DE61);
	KCALL_REL32(kernbase, 0x68CFEA, 0x68DE61);

	write_jmp(kernbase + 0x68E921, (uint64_t)hook_pfs_crypto__sceSblServiceCryptAsync);
	KCALL_REL32(kernbase, 0x68D284, 0x68E921);
	KCALL_REL32(kernbase, 0x68D71C, 0x68E921);
	KCALL_REL32(kernbase, 0x68D974, 0x68E921);
	KCALL_REL32(kernbase, 0x68DCED, 0x68E921);
	KCALL_REL32(kernbase, 0x68E11E, 0x68E921);
	KCALL_REL32(kernbase, 0x68E3B9, 0x68E921);
	KCALL_REL32(kernbase, 0x68E702, 0x68E921);

	// restore CR0
	__writecr0(CR0);

	uprintf("[jkpatch] installed fpkg hooks!");
}
