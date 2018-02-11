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

struct sbl_mapped_page_group;

#define SIZEOF_SBL_MAP_LIST_ENTRY 0x50 // sceSblDriverMapPages

TYPE_BEGIN(struct sbl_map_list_entry, SIZEOF_SBL_MAP_LIST_ENTRY);
TYPE_FIELD(struct sbl_map_list_entry* next, 0x00);
TYPE_FIELD(struct sbl_map_list_entry* prev, 0x08);
TYPE_FIELD(unsigned long cpu_va, 0x10);
TYPE_FIELD(unsigned int num_page_groups, 0x18);
TYPE_FIELD(unsigned long gpu_va, 0x20);
TYPE_FIELD(struct sbl_mapped_page_group* page_groups, 0x28);
TYPE_FIELD(unsigned int num_pages, 0x30);
TYPE_FIELD(unsigned long flags, 0x38);
TYPE_FIELD(struct proc *proc, 0x40);
TYPE_FIELD(void *vm_page, 0x48);
TYPE_END();

#define SBL_MSG_SERVICE_MAILBOX_MAX_SIZE 0x80

#define SELF_DIGEST_SIZE 0x20
#define SELF_CONTENT_ID_SIZE 0x13
#define SELF_RANDOM_PAD_SIZE 0x0D
#define SELF_MAX_HEADER_SIZE 0x4000

enum self_format {
	SELF_FORMAT_NONE,
	SELF_FORMAT_ELF,
	SELF_FORMAT_SELF,
};

#define SIZEOF_SELF_CONTEXT 0x60 // sceSblAuthMgrAuthHeader:bzero(sbl_authmgr_context, 0x60)

TYPE_BEGIN(struct self_context, SIZEOF_SELF_CONTEXT);
TYPE_FIELD(enum self_format format, 0x00);
TYPE_FIELD(int elf_auth_type, 0x04); /* auth id is based on that */
TYPE_FIELD(unsigned int total_header_size, 0x08);
TYPE_FIELD(int ctx_id, 0x1C);
TYPE_FIELD(uint64_t svc_id, 0x20);
TYPE_FIELD(int buf_id, 0x30);
TYPE_FIELD(uint8_t* header, 0x38);
TYPE_FIELD(struct mtx lock, 0x40);
TYPE_END();

#define SIZEOF_SELF_HEADER 0x20

TYPE_BEGIN(struct self_header, SIZEOF_SELF_HEADER);
TYPE_FIELD(uint32_t magic, 0x00);
#define SELF_MAGIC 0x1D3D154F
#define ELF_MAGIC  0x464C457F
TYPE_FIELD(uint8_t version, 0x04);
TYPE_FIELD(uint8_t mode, 0x05);
TYPE_FIELD(uint8_t endian, 0x06);
TYPE_FIELD(uint8_t attr, 0x07);
TYPE_FIELD(uint32_t key_type, 0x08);
TYPE_FIELD(uint16_t header_size, 0x0C);
TYPE_FIELD(uint16_t meta_size, 0x0E);
TYPE_FIELD(uint64_t file_size, 0x10);
TYPE_FIELD(uint16_t num_entries, 0x18);
TYPE_FIELD(uint16_t flags, 0x1A);
TYPE_END();

#define SIZEOF_SELF_ENTRY 0x20

TYPE_BEGIN(struct self_entry, SIZEOF_SELF_ENTRY);
TYPE_FIELD(uint64_t props, 0x00);
TYPE_FIELD(uint64_t offset, 0x08);
TYPE_FIELD(uint64_t file_size, 0x10);
TYPE_FIELD(uint64_t memory_size, 0x18);
TYPE_END();

#define SIZEOF_SELF_EX_INFO 0x40

TYPE_BEGIN(struct self_ex_info, SIZEOF_SELF_EX_INFO);
TYPE_FIELD(uint64_t paid, 0x00);
TYPE_FIELD(uint64_t ptype, 0x08);
#define SELF_PTYPE_FAKE 0x1
TYPE_FIELD(uint64_t app_version, 0x10);
TYPE_FIELD(uint64_t fw_version, 0x18);
TYPE_FIELD(uint8_t digest[SELF_DIGEST_SIZE], 0x20);
TYPE_END();

#define SIZEOF_SELF_AUTH_INFO 0x88 // sceSblAuthMgrIsLoadable2:bzero(auth_info, 0x88)

TYPE_BEGIN(struct self_auth_info, SIZEOF_SELF_AUTH_INFO);
TYPE_FIELD(uint64_t paid, 0x00);
TYPE_FIELD(uint64_t caps[4], 0x08);
TYPE_FIELD(uint64_t attrs[4], 0x28);
TYPE_FIELD(uint8_t unk[0x40], 0x48);
TYPE_END();

#define SIZEOF_SELF_FAKE_AUTH_INFO (sizeof(uint64_t) + SIZEOF_SELF_AUTH_INFO)

TYPE_BEGIN(struct self_fake_auth_info, SIZEOF_SELF_FAKE_AUTH_INFO);
TYPE_FIELD(uint64_t size, 0x00);
TYPE_FIELD(struct self_auth_info info, 0x08);
TYPE_END();

#define CONTENT_KEY_SEED_SIZE 0x10
#define SELF_KEY_SEED_SIZE 0x10
#define EEKC_SIZE 0x20

struct ekc {
	uint8_t content_key_seed[CONTENT_KEY_SEED_SIZE];
	uint8_t self_key_seed[SELF_KEY_SEED_SIZE];
};

#define SIZEOF_SBL_KEY_DESC 0x7C // sceSblKeymgrSetKey

union sbl_key_desc {
	struct {
		uint16_t cmd;
		uint16_t pad;
		uint8_t key[0x20];
		uint8_t seed[0x10];
	} pfs;

	uint8_t raw[SIZEOF_SBL_KEY_DESC];
};
TYPE_CHECK_SIZE(union sbl_key_desc, SIZEOF_SBL_KEY_DESC);

#define SIZEOF_SBL_KEY_RBTREE_ENTRY 0xA8 // sceSblKeymgrSetKey

#define TYPE_SBL_KEY_RBTREE_ENTRY_DESC_OFFSET 0x04
#define TYPE_SBL_KEY_RBTREE_ENTRY_LOCKED_OFFSET 0x80

TYPE_BEGIN(struct sbl_key_rbtree_entry, SIZEOF_SBL_KEY_RBTREE_ENTRY);
TYPE_FIELD(uint32_t handle, 0x00);
TYPE_FIELD(union sbl_key_desc desc, TYPE_SBL_KEY_RBTREE_ENTRY_DESC_OFFSET);
TYPE_FIELD(uint32_t locked, TYPE_SBL_KEY_RBTREE_ENTRY_LOCKED_OFFSET);
TYPE_FIELD(struct sbl_key_rbtree_entry* left, 0x88);
TYPE_FIELD(struct sbl_key_rbtree_entry* right, 0x90);
TYPE_FIELD(struct sbl_key_rbtree_entry* parent, 0x98);
TYPE_FIELD(uint32_t set, 0xA0);
TYPE_END();

#define RIF_DIGEST_SIZE 0x10
#define RIF_DATA_SIZE 0x90
#define RIF_KEY_TABLE_SIZE 0x230
#define RIF_MAX_KEY_SIZE 0x20
#define RIF_PAYLOAD_SIZE (RIF_DIGEST_SIZE + RIF_DATA_SIZE)

#define SIZEOF_ACTDAT 0x200

TYPE_BEGIN(struct actdat, SIZEOF_ACTDAT);
TYPE_FIELD(uint32_t magic, 0x00);
TYPE_FIELD(uint16_t version_major, 0x04);
TYPE_FIELD(uint16_t version_minor, 0x06);
TYPE_FIELD(uint64_t account_id, 0x08);
TYPE_FIELD(uint64_t start_time, 0x10);
TYPE_FIELD(uint64_t end_time, 0x18);
TYPE_FIELD(uint64_t flags, 0x20);
TYPE_FIELD(uint32_t unk3, 0x28);
TYPE_FIELD(uint32_t unk4, 0x2C);
TYPE_FIELD(uint8_t open_psid_hash[0x20], 0x60);
TYPE_FIELD(uint8_t static_per_console_data_1[0x20], 0x80);
TYPE_FIELD(uint8_t digest[0x10], 0xA0);
TYPE_FIELD(uint8_t key_table[0x20], 0xB0);
TYPE_FIELD(uint8_t static_per_console_data_2[0x10], 0xD0);
TYPE_FIELD(uint8_t static_per_console_data_3[0x20], 0xE0);
TYPE_FIELD(uint8_t signature[0x100], 0x100);
TYPE_END();

#define SIZEOF_RIF 0x400

TYPE_BEGIN(struct rif, SIZEOF_RIF);
TYPE_FIELD(uint32_t magic, 0x00);
TYPE_FIELD(uint16_t version_major, 0x04);
TYPE_FIELD(uint16_t version_minor, 0x06);
TYPE_FIELD(uint64_t account_id, 0x08);
TYPE_FIELD(uint64_t start_time, 0x10);
TYPE_FIELD(uint64_t end_time, 0x18);
TYPE_FIELD(char content_id[0x30], 0x20);
TYPE_FIELD(uint16_t format, 0x50);
TYPE_FIELD(uint16_t drm_type, 0x52);
TYPE_FIELD(uint16_t content_type, 0x54);
TYPE_FIELD(uint16_t sku_flag, 0x56);
TYPE_FIELD(uint64_t content_flags, 0x58);
TYPE_FIELD(uint32_t iro_tag, 0x60);
TYPE_FIELD(uint32_t ekc_version, 0x64);
TYPE_FIELD(uint16_t unk3, 0x6A);
TYPE_FIELD(uint16_t unk4, 0x6C);
TYPE_FIELD(uint8_t digest[0x10], 0x260);
TYPE_FIELD(uint8_t data[RIF_DATA_SIZE], 0x270);
TYPE_FIELD(uint8_t signature[0x100], 0x300);
TYPE_END();

union keymgr_payload {
	struct {
		uint32_t cmd;
		uint32_t status;
		uint64_t data;
	};

	uint8_t buf[0x80];
};

union keymgr_request {
	struct {
		uint32_t type;
		uint8_t key[RIF_MAX_KEY_SIZE];
		uint8_t data[RIF_DIGEST_SIZE + RIF_DATA_SIZE];
	} decrypt_rif;

	struct {
		struct rif rif;
		uint8_t key_table[RIF_KEY_TABLE_SIZE];
		uint64_t timestamp;
		int status;
	} decrypt_entire_rif;
};
union keymgr_response {
	struct {
		uint32_t type;
		uint8_t key[RIF_MAX_KEY_SIZE];
		uint8_t data[RIF_DIGEST_SIZE + RIF_DATA_SIZE];
	} decrypt_rif;

	struct {
		uint8_t raw[SIZEOF_RIF];
	} decrypt_entire_rif;
};

#define EKPFS_SIZE 0x20
#define EEKPFS_SIZE 0x100
#define PFS_SEED_SIZE 0x10
#define PFS_FINAL_KEY_SIZE 0x20

#define SIZEOF_PFS_KEY_BLOB 0x158
struct pfs_key_blob {
	uint8_t ekpfs[EKPFS_SIZE];
	uint8_t eekpfs[EEKPFS_SIZE];
	struct ekc eekc;
	uint32_t key_ver;
	uint32_t pubkey_ver;
	uint32_t type;
	uint32_t finalized;
	uint32_t is_disc;
	uint32_t pad;
};
typedef struct pfs_key_blob pfs_key_blob_t;
TYPE_CHECK_SIZE(pfs_key_blob_t, SIZEOF_PFS_KEY_BLOB);

#define CCP_MAX_PAYLOAD_SIZE 0x88
#define CCP_OP(cmd) (cmd >> 24)
#define CCP_OP_XTS 2
#define CCP_OP_HMAC 9
#define CCP_USE_KEY_HANDLE (1 << 20)

union ccp_op {
	struct {
		uint32_t cmd;
		uint32_t status;
	} common;

	uint8_t buf[CCP_MAX_PAYLOAD_SIZE];
};
struct ccp_link {
	void *p;
};
struct ccp_msg {
	union ccp_op op;

	uint32_t index;
	uint32_t result;

	TAILQ_ENTRY(ccp_msg) next;

	uint64_t message_id;
	LIST_ENTRY(ccp_link) links;
};
struct ccp_req {
	TAILQ_HEAD(, ccp_msg) msgs;

	void (*cb)(void* arg, int result);
	void* arg;

	uint64_t message_id;
	LIST_ENTRY(ccp_link) links;
};

#define SBL_MSG_SERVICE_MAILBOX_MAX_SIZE 0x80

struct rsa_buffer {
	uint8_t* ptr;
	size_t size;
};

#define SIZEOF_RSA_KEY 0x48

TYPE_BEGIN(struct rsa_key, SIZEOF_RSA_KEY);
TYPE_FIELD(uint8_t* p, 0x20);
TYPE_FIELD(uint8_t* q, 0x28);
TYPE_FIELD(uint8_t* dmp1, 0x30);
TYPE_FIELD(uint8_t* dmq1, 0x38);
TYPE_FIELD(uint8_t* iqmp, 0x40);
TYPE_END();

#endif
