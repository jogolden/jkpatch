/* golden */
/* 1/30/2018 */

#include "proc.h"

struct proc *proc_find_by_name(const char *name) {
	struct proc *p;

	if (!name) {
		goto error;
	}

	uint64_t kernbase = getkernbase();
	p = *(struct proc **)(kernbase + __allproc);

	do {
		if (!memcmp(p->p_comm, name, strlen(name))) {
			return p;
		}
	} while ((p = p->p_forw));

error:
	return NULL;
}

struct proc *proc_find_by_pid(int pid) {
	struct proc *p;

	uint64_t kernbase = getkernbase();
	p = *(struct proc **)(kernbase + __allproc);

	do {
		if (p->pid == pid) {
			return p;
		}
	} while ((p = p->p_forw));

	return NULL;
}

int hexdump(const void *data, size_t size) {

	unsigned char *d = (unsigned char *)data;
	size_t consoleSize = 16;
	char b[consoleSize + 3];
	size_t i;

	if (data == NULL) {
		return -1;
	}
	b[0] = '|';
	b[consoleSize + 1] = '|';
	b[consoleSize + 2] = '\0';

	printf("\n-------HEX DUMP------\n");
	for (i = 0; i < size; i++)
	{
		if ((i % consoleSize) == 0)
		{
			if (i != 0) {
				printf("  %s\n", b);
			}
			printf("%016lx ", (unsigned char *)data + i);
		}

		if (i % consoleSize == 8)
			printf(" ");
		printf(" %02x", d[i]);

		if (d[i] >= ' ' && d[i] <= '~')
			b[i % consoleSize + 1] = d[i];

		else
			b[i % consoleSize + 1] = '.';
	}

	while ((i % consoleSize) != 0)
	{

		if (i % consoleSize == 8)
			printf("    ");

		else
			printf("   ");
		b[i % consoleSize + 1] = '.';
		i++;
	}

	printf("  %s\n", b);
	return 0;
}

int proc_get_vm_map(struct proc *p, struct proc_vm_map_entry **entries, size_t *num_entries) {
	uint64_t ents = NULL;
	size_t num = NULL;

	struct proc_vm_map_entry *info = NULL;

	uint64_t vm = vmspace_acquire_ref(p);

	// vm_map is first field in vmspace so idrc fuck it, clean it later
	uint64_t map = vm;

	// TODO: fix this and make up string/number args
	const char dbg[] = "W:\\Build\\J01660900\\sys\\freebsd\\sys\\kern\\sys_process.c";

	vm_map_lock_read(map, dbg, 442);

	// vm_map_entry
	// 0x20 is start int64
	// 0x28 is end int64
	// 0x50 is offset int64
	// 0x5C is protection int16
	// 0x88 is some sort of map name

	if (vm_map_lookup_entry(map, 0, &ents)) {
		vm_map_unlock_read(map, dbg, 442);
		vmspace_free(vm);
		return 1;
	}

	// count number
	uint64_t e0 = ents;
	do {
		num++;
		ents = *(uint64_t *)(ents + 8);
	} while (ents != e0);

	info = (struct proc_vm_map_entry *)alloc(num * sizeof(struct proc_vm_map_entry));
	//memset(info, NULL, num * sizeof(struct proc_vm_map_entry));

	// fill data
	ents = e0;
	int i = 0;
	do {
		info[i].start = *(uint64_t *)(ents + 0x20);
		info[i].end = *(uint64_t *)(ents + 0x28);
		info[i].offset = *(uint64_t *)(ents + 0x50);
		info[i].prot = *(uint16_t *)(ents + 0x5C) & (*(uint16_t *)(ents + 0x5C) >> 8);

		char *name = (char *)(ents + 0x88);
		memcpy(info[i].name, name, 32);

		i++;
		ents = *(uint64_t *)(ents + 8);
	} while (ents != e0);

	// clean up
	vm_map_unlock_read(map, dbg, 442);
	vmspace_free(vm);

	if (entries) {
		*entries = info;
	}

	if (num_entries) {
		*num_entries = num;
	}

	info = NULL;
	num = 0;

	return 0;
}

int proc_rw_mem(struct proc *p, void *ptr, size_t size, void *data, size_t *n, int write) {
	struct thread *td = curthread();
	struct iovec iov;
	struct uio uio;
	int ret;

	if (!p) {
		ret = -1;
		goto error;
	}

	if (size == 0) {
		if (n)
			*n = 0;
		ret = 0;
		goto error;
	}

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = (uint64_t)data;
	iov.iov_len = size;

	memset(&uio, 0, sizeof(uio));
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = (uint64_t)ptr;
	uio.uio_resid = (uint64_t)size;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = write ? UIO_WRITE : UIO_READ;
	uio.uio_td = td;

	ret = proc_rwmem(p, &uio);

	if (n) {
		*n = (size_t)((uint64_t)size - uio.uio_resid);
	}

error:
	return ret;
}

inline int proc_read_mem(struct proc *p, void *ptr, size_t size, void *data, size_t *n) {
	return proc_rw_mem(p, ptr, size, data, n, 0);
}

inline int proc_write_mem(struct proc *p, void *ptr, size_t size, void *data, size_t *n) {
	return proc_rw_mem(p, ptr, size, data, n, 1);
}
