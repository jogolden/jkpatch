/* golden */
/* 1/2/2018 */

#include "fpkg.h"

struct fake_key_desc s_fake_keys[MAX_FAKE_KEYS];
struct sx s_fake_keys_lock;

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
	memcpy(d, &index, sizeof(index)); // ptr alias rules
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

int shellcore_fpkg_patch() {
	uint8_t *text_seg_base = NULL;
	size_t n;

	struct proc_vm_map_entry *entries = NULL;
	size_t num_entries;

	int ret = 0;

	// all offsets below are belongs to functions that parses .pkg files
	uint32_t call_ofs_for__xor__eax_eax__3nop[] = {
		0x1486BB, // call sceKernelIsGenuineCEX
		0x6E523B, // call sceKernelIsGenuineCEX
		0x852C6B, // call sceKernelIsGenuineCEX
		0x1486E7, // call nidf_libSceDipsw_0xD21CE9E2F639A83C
		0x6E5267, // call nidf_libSceDipsw_0xD21CE9E2F639A83C
		0x852C97, // call nidf_libSceDipsw_0xD21CE9E2F639A83C
	};

	struct proc *ssc = proc_find_by_name("SceShellCore");

	if (!ssc) {
		ret = 1;
		goto error;
	}

	if (proc_get_vm_map(ssc, &entries, &num_entries)) {
		ret = 1;
		goto error;
	}

	for (int i = 0; i < num_entries; i++) {
		if (entries[i].prot == (PROT_READ | PROT_EXEC)) {
			text_seg_base = (uint8_t *)entries[i].start;
			break;
		}
	}

	if (!text_seg_base) {
		ret = 1;
		goto error;
	}

	// enable installing of debug packages
	for (int i = 0; i < COUNT_OF(call_ofs_for__xor__eax_eax__3nop); i++) {
		ret = proc_write_mem(ssc, (void *)(text_seg_base + call_ofs_for__xor__eax_eax__3nop[i]), 5, "\x31\xC0\x90\x90\x90", &n);
		if (ret) {
			goto error;
		}
	}

	// this offset corresponds to "fake\0" string in the Shellcore's memory
	ret = proc_write_mem(ssc, (void *)(text_seg_base + 0xD40F28), 5, "free\0", &n);
	if (ret) {
		goto error;
	}

error:
	if (entries) {
		dealloc(entries);
	}

	return ret;
}

void install_fpkg_hooks() {
	// disable write protect
	uint64_t CR0 = __readcr0();
	__writecr0(CR0 & ~CR0_WP);

	uint64_t kernbase = getkernbase();

	sx_init_flags(&s_fake_keys_lock, "fake_keys_lock", 0);
	memset(s_fake_keys, 0, sizeof(s_fake_keys));

	write_jmp(kernbase + 0x62CF10, (uint64_t)hook_npdrm_decrypt_isolated_rif__sceSblKeymgrSmCallfunc);
	KCALL_REL32(kernbase, 0x62DF00, 0x62CF10);

	write_jmp(kernbase + 0x64D731, (uint64_t)hook_npdrm_decrypt_new_rif__sceSblKeymgrSmCallfunc);
	KCALL_REL32(kernbase, 0x62ECDE, 0x64D731);

	write_jmp(kernbase + 0x64D381, (uint64_t)hook_sceSblPfsKeymgrIoctl__sceSblPfsKeymgrGenEKpfsForGDGPAC);
	KCALL_REL32(kernbase, 0x607045, 0x64D381);
	KCALL_REL32(kernbase, 0x6070E1, 0x64D381);

	write_jmp(kernbase + 0x6953A1, (uint64_t)hook_pfs_sbl_init__sceSblPfsSetKey);
	KCALL_REL32(kernbase, 0x69DB4A, 0x6953A1);
	KCALL_REL32(kernbase, 0x69DBD8, 0x6953A1);

	write_jmp(kernbase + 0x6AD171, (uint64_t)hook_pfs_crypto__sceSblServiceCryptAsync);
	KCALL_REL32(kernbase, 0x69DDE4, 0x6AD171);
	KCALL_REL32(kernbase, 0x69E28C, 0x6AD171);
	KCALL_REL32(kernbase, 0x69E4E8, 0x6AD171);
	KCALL_REL32(kernbase, 0x69E85D, 0x6AD171);
	KCALL_REL32(kernbase, 0x69EC7E, 0x6AD171);
	KCALL_REL32(kernbase, 0x69EF0D, 0x6AD171);
	KCALL_REL32(kernbase, 0x69F252, 0x6AD171);

	// restore CR0
	__writecr0(CR0);

	uprintf("[jkpatch] installed fpkg hooks!");
}
