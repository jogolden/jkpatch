/* golden */
/* 2/1/2018 */

#ifndef _RPC_H
#define _RPC_H

#include "jkpayload.h"
#include "../librpc/rpcasm/rpcasm.h"
#include "net.h"
#include "proc.h"

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
#define RPC_PROC_ELF		0xBD000007
#define RPC_END				0xBD000008
#define RPC_REBOOT			0xBD000009
#define RPC_KERN_BASE		0xBD00000A
#define RPC_KERN_READ		0xBD00000B
#define RPC_KERN_WRITE		0xBD00000C

#define RPC_VALID_CMD(cmd)	(((cmd & 0xFF000000) >> 24) == 0xBD)

#define RPC_MAX_DATA_LEN	8192

// rpc status
#define RPC_SUCCESS				0x80000000
#define RPC_TOO_MUCH_DATA		0xF0000001
#define RPC_READ_ERROR			0xF0000002
#define RPC_WRITE_ERROR			0xF0000003
#define RPC_LIST_ERROR			0xF0000004
#define RPC_INFO_ERROR			0xF0000005
#define RPC_INFO_NO_MAP			0x80000006
#define RPC_NO_PROC				0xF0000007
#define RPC_INSTALL_ERROR		0xF0000008
#define RPC_CALL_ERROR			0xF0000009
#define RPC_ELF_ERROR			0xF000000A

#define RPC_FATAL_STATUS(s) ((s >> 28) == 15)

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

struct rpc_proc_install1 {
	uint32_t pid;
} __attribute__((packed));

struct rpc_proc_install2 {
	uint32_t pid;
	uint64_t rpcstub;
} __attribute__((packed));

#define RPC_PROC_INSTALL1_SIZE 4
#define RPC_PROC_INSTALL2_SIZE 12

struct rpc_proc_call1 {
	uint32_t pid;
	uint64_t rpcstub;
	uint64_t rpc_rip;
	uint64_t rpc_rdi;
	uint64_t rpc_rsi;
	uint64_t rpc_rdx;
	uint64_t rpc_rcx;
	uint64_t rpc_r8;
	uint64_t rpc_r9;
} __attribute__((packed));

struct rpc_proc_call2 {
	uint32_t pid;
	uint64_t rpc_rax;
} __attribute__((packed));

#define RPC_PROC_CALL1_SIZE 68
#define RPC_PROC_CALL2_SIZE 12

struct rpc_proc_elf {
	uint32_t pid;
	uint32_t size;
} __attribute__((packed));

#define RPC_PROC_ELF_SIZE 8

struct rpc_kern_base {
	uint64_t kernbase;
} __attribute__((packed));

#define RPC_KERN_BASE_SIZE 8

struct rpc_kern_read {
	uint64_t address;
	uint32_t length;
} __attribute__((packed));

#define RPC_KERN_READ_SIZE 12

struct rpc_kern_write {
	uint64_t address;
	uint32_t length;
} __attribute__((packed));

#define RPC_KERN_WRITE_SIZE 12

extern struct proc *krpcproc;

void init_rpc();

#endif
