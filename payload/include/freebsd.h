/* golden */
/* 1/2/2018 */

// contains function prototypes, contants, and structures for freebsd (specifcally PS4)

#ifndef _FREEBSD_H
#define _FREEBSD_H

#include "sparse.h"

typedef int vm_prot_t;
typedef uint64_t vm_offset_t;
typedef uint64_t vm_map_t;
typedef uint64_t vm_size_t;
typedef unsigned long size_t;
#define	VM_PROT_NONE	((vm_prot_t) 0x00)
#define VM_PROT_READ	((vm_prot_t) 0x01)	/* read permission */
#define VM_PROT_WRITE	((vm_prot_t) 0x02)	/* write permission */
#define VM_PROT_EXECUTE	((vm_prot_t) 0x04)	/* execute permission */
#define VM_PROT_DEFAULT	(VM_PROT_READ|VM_PROT_WRITE)
#define VM_PROT_ALL			(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)
#define VM_PROT_NO_CHANGE	((vm_prot_t) 0x08)
#define VM_PROT_COPY		((vm_prot_t) 0x10)
#define VM_PROT_WANTS_COPY	((vm_prot_t) 0x10)

// errno
#define EPERM		1
#define ENOENT		2
#define ESRCH		3
#define EINTR		4
#define EIO			5
#define ENXIO		6
#define E2BIG		7
#define ENOEXEC		8
#define EBADF		9
#define ECHILD		10
#define EAGAIN		11
#define ENOMEM		12
#define EACCES		13
#define EFAULT		14
#define ENOTBLK		15
#define EBUSY		16
#define EEXIST		17
#define EXDEV		18
#define ENODEV		19
#define ENOTDIR		20
#define EISDIR		21
#define EINVAL		22
#define ENFILE		23
#define EMFILE		24
#define ENOTTY		25
#define ETXTBSY		26
#define EFBIG		27
#define ENOSPC		28
#define ESPIPE		29
#define EROFS		30
#define EMLINK		31
#define EPIPE		32
#define EDOM		33
#define ERANGE		34
#define ENOMSG		35
#define EIDRM		36
#define ECHRNG		37
#define EL2NSYNC	38
#define EL3HLT		39
#define EL3RST		40
#define ELNRNG		41
#define EUNATCH		42
#define ENOCSI		43
#define EL2HLT		44
#define EDEADLK		45
#define ENOLCK		46
#define ECANCELED	47
#define ENOTSUP		48

#define	TRACEBUF	struct qm_trace trace;

#define	TAILQ_FIRST(head) ((head)->tqh_first)
#define	TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define	TAILQ_HEAD(name, type)									\
struct name {													\
	struct type *tqh_first;	/* first element */					\
	struct type **tqh_last;	/* addr of last next element */		\
	TRACEBUF													\
}

#define	TAILQ_ENTRY(type)											\
struct {															\
	struct type *tqe_next;	/* next element */						\
	struct type **tqe_prev;	/* address of previous next element */	\
	TRACEBUF														\
}

#define	LIST_ENTRY(type)											\
struct {															\
	struct type *le_next;	/* next element */						\
	struct type **le_prev;	/* address of previous next element */	\
}

#define	TAILQ_FOREACH(var, head, field)				\
	for ((var) = TAILQ_FIRST((head));				\
	    (var);										\
(var) = TAILQ_NEXT((var), field))

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

struct qm_trace {
	char * lastfile;
	int lastline;
	char * prevfile;
	int prevline;
};

enum uio_rw {
	UIO_READ,
	UIO_WRITE
};

enum uio_seg {
	UIO_USERSPACE,		/* from user data space */
	UIO_SYSSPACE,		/* from system space */
	UIO_USERISPACE		/* from user I space */
};

struct __iovec {
	uint64_t iov_base;
	size_t iov_len;
};

TYPE_BEGIN(struct uio, 0x30);
TYPE_FIELD(uint64_t uio_iov, 0);
TYPE_FIELD(uint32_t uio_iovcnt, 8);
TYPE_FIELD(uint64_t uio_offset, 0x10);
TYPE_FIELD(uint64_t uio_resid, 0x18);
TYPE_FIELD(uint32_t uio_segflg, 0x20);
TYPE_FIELD(uint32_t uio_rw, 0x24);
TYPE_FIELD(struct thread *uio_td, 0x28);
TYPE_END();

struct lock_object {
	const char* lo_name;
	uint32_t lo_flags;
	uint32_t lo_data;
	void* lo_witness;
};

struct mtx {
	struct lock_object lock_object;
	volatile void* mtx_lock;
};

struct sx {
	struct lock_object lock_object;
	volatile uintptr_t sx_lock;
};

struct auditinfo_addr {
	uint8_t useless[184];
};

struct ucred {
	uint32_t cr_ref;					// reference count		0x0000
	uint32_t cr_uid;					// effective user id	0x0004
	uint32_t cr_ruid;					// real user id			0x0008
	uint32_t useless2;					// 						0x000C
	uint32_t useless3;					//
	uint32_t cr_rgid;					// real group id
	uint32_t useless4;					//
	void *useless5;						//
	void *useless6;						//
	void *cr_prison;					// jail(2)				0x0030
	void *useless7;						//
	uint32_t useless8;					//
	void *useless9[2];					//
	void *useless10;					//
	struct auditinfo_addr cr_audit;		//
	uint32_t *cr_groups;				// groups
	uint32_t useless12;					//
};

struct filedesc {
	void *useless1[3];
	void *fd_rdir;
	void *fd_jdir;
};

TYPE_BEGIN(struct proc, 0x800); // XXX: random, don't use directly without fixing it
TYPE_FIELD(struct proc *p_forw, 0);
TYPE_FIELD(struct ucred *p_ucred, 0x40);
TYPE_FIELD(struct filedesc *p_fd, 0x48);
TYPE_FIELD(int pid, 0xB0);
TYPE_FIELD(char p_comm[32], 0x3F0);
TYPE_END();

TYPE_BEGIN(struct thread, 0x3D8); // XXX: random, don't use directly without fixing it
TYPE_FIELD(struct proc *td_proc, 8);
TYPE_FIELD(struct ucred *td_ucred, 0x130);
TYPE_FIELD(char td_name[32], 0x284);
TYPE_END();

static inline struct thread *curthread(void) {
	struct thread* td;
	__asm__ __volatile__ (
	    "mov %0, %%gs:0"
	    : "=r"(td)
	);

	return td;
}

#endif

