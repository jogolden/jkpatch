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

int proc_get_vm_map(struct proc *p, struct proc_vm_map_entry **entries, size_t *num_entries) {
	struct proc_vm_map_entry *info = NULL;
	struct vm_map_entry *entry = NULL;

	struct vmspace *vm = vmspace_acquire_ref(p);
	if (!vm) {
		return 1;
	}

	struct vm_map *map = &vm->vm_map;

	int num = map->nentries;
	if (!num) {
		return 0;
	}

	vm_map_lock_read(map);

	if (vm_map_lookup_entry(map, NULL, &entry)) {
		vm_map_unlock_read(map);
		vmspace_free(vm);
		return 1;
	}

	info = (struct proc_vm_map_entry *)alloc(num * sizeof(struct proc_vm_map_entry));
	if (!info) {
		vm_map_unlock_read(map);
		vmspace_free(vm);
		return 1;
	}

	for (int i = 0; i < num; i++) {
		info[i].start = entry->start;
		info[i].end = entry->end;
		info[i].offset = entry->offset;
		info[i].prot = entry->prot & (entry->prot >> 8);
		memcpy(info[i].name, entry->name, sizeof(info[i].name));

		entry = entry->next;
		if (!entry) {
			break;
		}
	}

	vm_map_unlock_read(map);
	vmspace_free(vm);

	if (entries) {
		*entries = info;
	}

	if (num_entries) {
		*num_entries = num;
	}

	return 0;
}

int proc_rw_mem(struct proc *p, void *ptr, size_t size, void *data, size_t *n, int write) {
	struct thread *td = curthread();
	struct iovec iov;
	struct uio uio;
	int ret = 0;

	if (!p) {
		ret = -1;
		goto error;
	}

	if (size == 0) {
		if (n) {
			*n = 0;
		}

		ret = 0;
		goto error;
	}

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = (uint64_t)data;
	iov.iov_len = size;

	memset(&uio, 0, sizeof(uio));
	uio.uio_iov = (uint64_t)&iov;
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
