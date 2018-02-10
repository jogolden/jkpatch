/* golden */
/* 2/1/2018 */

#ifndef _RPC_H
#define _RPC_H

#include "jkpayload.h"
#include "net.h"
#include "proc.h"

// todo: clean up networking and code
// todo: write better c style code

// network
#define RPC_PORT			733

// magic
#define RPC_PACKET_MAGIC	0xBDAABBCC

// rpc cmds
#define RPC_PROC_READ		0xBD000001
#define RPC_PROC_WRITE		0xBD000002
#define RPC_PROC_LIST		0xBD000003
#define RPC_PROC_INFO		0xBD000004
#define RPC_PROC_INTALL		0xBD000005
#define RPC_PROC_CALL		0xBD000006
#define RPC_PROC_END		0xBD000007

#define RPC_VALID_CMD(cmd)	(((cmd & 0xFF000000) >> 24) == 0xBD)

#define RPC_MAX_DATA_LEN	4096

// rpc status
#define RPC_SUCCESS				0x80000000
#define RPC_TOO_MUCH_DATA		0x80000001
#define RPC_READ_ERROR			0x80000002
#define RPC_WRITE_ERROR			0x80000003
#define RPC_LIST_ERROR			0x80000004
#define RPC_INFO_ERROR			0x80000005
#define RPC_INFO_NO_MAP			0x80000006
#define RPC_NO_PROC				0x80000007

struct rpc_packet {
	uint32_t magic;
	uint32_t cmd;
	uint32_t datalen;
	// (field not actually part of packet, comes after)
	uint8_t *data;
} __attribute__((packed));

#define RPC_PACKET_SIZE 12

struct rpc_status {
	uint32_t magic;
	uint32_t status;
} __attribute__((packed));

#define RPC_STATUS_SIZE 8

// specific cmd structures
struct rpc_proc_read {
	uint32_t pid;
	uint64_t address;
	uint32_t length;
} __attribute__((packed));

#define RPC_PROC_READ_SIZE 16

struct rpc_proc_write {
	uint32_t pid;
	uint64_t address;
	uint32_t length;
} __attribute__((packed));

#define RPC_PROC_WRITE_SIZE 16

struct rpc_proc_list {
	char name[32];
	uint32_t pid;
} __attribute__((packed));

#define RPC_PROC_LIST_SIZE 36

struct rpc_proc_info1 {
	uint32_t pid;
} __attribute__((packed));

struct rpc_proc_info2 {
	char name[32];
	uint64_t start;
	uint64_t end;
	uint64_t offset;
	uint32_t prot;
} __attribute__((packed));

#define RPC_PROC_INFO1_SIZE 4
#define RPC_PROC_INFO2_SIZE 60

struct handler_arg {
	uint32_t fd;
};

//int rpc_cmd_handler(int fd, struct rpc_packet *packet)
//int rpc_handler(struct handler_arg *arg);
//void rpc_server_thread(void *arg);
void init_rpc();

#endif
