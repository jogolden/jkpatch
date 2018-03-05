/* golden */
/* 2/1/2018 */

#include "rpc.h"

struct proc *krpcproc;

int rpc_proc_load(struct proc *p, uint64_t address) {
	void *rpcldraddr = NULL;
	void *stackaddr = NULL;
	struct proc_vm_map_entry *entries = NULL;
	size_t num_entries = 0;
	size_t n = 0;
	int r = 0;

	uint64_t ldrsize = sizeof(rpcldr);
	ldrsize += (PAGE_SIZE - (ldrsize % PAGE_SIZE));

	uint64_t stacksize = 0x80000;

	// allocate rpc ldr
	r = proc_allocate(p, &rpcldraddr, ldrsize);
	if (r) {
		goto error;
	}

	// allocate stack
	r = proc_allocate(p, &stackaddr, stacksize);
	if (r) {
		goto error;
	}

	// write loader
	r = proc_write_mem(p, rpcldraddr, sizeof(rpcldr), (void *)rpcldr, &n);
	if (r) {
		goto error;
	}

	// patch suword_lwpid
	// has a check to see if child_tid/parent_tid is in kernel memory, and it in so patch it
	uint64_t kernbase = getkernbase();
	uint64_t CR0 = __readcr0();
	uint16_t *suword_lwpid1 = (uint16_t *)(kernbase + 0x14AB92);
	uint16_t *suword_lwpid2 = (uint16_t *)(kernbase + 0x14ABA1);
	__writecr0(CR0 & ~CR0_WP);
	*suword_lwpid1 = 0x9090;
	*suword_lwpid2 = 0x9090;
	__writecr0(CR0);

	// donor thread
	struct thread *thr = TAILQ_FIRST(&p->p_threads);

	// find libkernel base
	r = proc_get_vm_map(p, &entries, &num_entries);
	if (r) {
		goto error;
	}

	// offsets are for 4.55 libraries
	// todo: write patch finder

	// libkernel.sprx
	// 0x115C0 scePthreadCreate
	// 0x7CD20 thr_initial

	// libkernel_web.sprx
	// 0x115C0 scePthreadCreate
	// 0x7CD20 thr_initial

	// libkernel_sys.sprx
	// 0x120F0 scePthreadCreate
	// 0x80D20 thr_initial

	uint64_t _scePthreadAttrInit = 0, _scePthreadAttrSetstacksize = 0, _scePthreadCreate = 0, _thr_initial = 0;
	for (int i = 0; i < num_entries; i++) {
		if (entries[i].prot != (PROT_READ | PROT_EXEC)) {
			continue;
		}

		if (!memcmp(entries[i].name, "libkernel.sprx", 14) ||
		        !memcmp(entries[i].name, "libkernel_web.sprx", 18)) {
			_scePthreadAttrInit = entries[i].start + 0x11180;
			_scePthreadAttrSetstacksize = entries[i].start + 0x111A0;
			_scePthreadCreate = entries[i].start + 0x115C0;
			_thr_initial = entries[i].start + 0x7CD20;
			break;
		}

		if (!memcmp(entries[i].name, "libkernel_sys.sprx", 18)) {
			_scePthreadAttrInit = entries[i].start + 0x11CB0;
			_scePthreadAttrSetstacksize = entries[i].start + 0x11CD0;
			_scePthreadCreate = entries[i].start + 0x120F0;
			_thr_initial = entries[i].start + 0x80D20;
			break;
		}
	}

	if (!_scePthreadAttrInit) {
		goto error;
	}

	// write variables
	r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, stubentry), sizeof(address), (void *)&address, &n);
	if (r) {
		goto error;
	}

	r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadAttrInit), sizeof(_scePthreadAttrInit), (void *)&_scePthreadAttrInit, &n);
	if (r) {
		goto error;
	}

	r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadAttrSetstacksize), sizeof(_scePthreadAttrSetstacksize), (void *)&_scePthreadAttrSetstacksize, &n);
	if (r) {
		goto error;
	}

	r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadCreate), sizeof(_scePthreadCreate), (void *)&_scePthreadCreate, &n);
	if (r) {
		goto error;
	}

	r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, thr_initial), sizeof(_thr_initial), (void *)&_thr_initial, &n);
	if (r) {
		goto error;
	}

	// execute loader
	uint64_t ldrentryaddr = (uint64_t)rpcldraddr + *(uint64_t *)(rpcldr + 4);
	r = create_thread(thr, NULL, (void *)ldrentryaddr, NULL, stackaddr, stacksize, NULL, NULL, NULL, 0, NULL);
	if (r) {
		goto error;
	}

	// wait until loader is done
	uint8_t ldrdone = 0;
	while (!ldrdone) {
		r = proc_read_mem(p, (void *)(rpcldraddr + offsetof(struct rpcldr_header, ldrdone)), sizeof(ldrdone), &ldrdone, &n);
		if (r) {
			goto error;
		}
	}

error:
	if (entries) {
		dealloc(entries);
	}

	if (rpcldraddr) {
		proc_deallocate(p, rpcldraddr, ldrsize);
	}

	if (stackaddr) {
		proc_deallocate(p, stackaddr, stacksize);
	}

	return r;
}

inline struct Elf64_Phdr *elf_pheader(struct Elf64_Ehdr *hdr) {
	if (!hdr->e_phoff) {
		return NULL;
	}

	return (struct Elf64_Phdr *)((uint64_t)hdr + hdr->e_phoff);
}

inline struct Elf64_Phdr *elf_segment(struct Elf64_Ehdr *hdr, int idx) {
	uint64_t addr = (uint64_t)elf_pheader(hdr);
	if (!addr) {
		return NULL;
	}

	return (struct Elf64_Phdr *)(addr + (hdr->e_phentsize * idx));
}

inline struct Elf64_Shdr *elf_sheader(struct Elf64_Ehdr *hdr) {
	if (!hdr->e_shoff) {
		return NULL;
	}

	return (struct Elf64_Shdr *)((uint64_t)hdr + hdr->e_shoff);
}

inline struct Elf64_Shdr *elf_section(struct Elf64_Ehdr *hdr, int idx) {
	uint64_t addr = (uint64_t)elf_sheader(hdr);
	if (!addr) {
		return NULL;
	}

	return (struct Elf64_Shdr *)(addr + (hdr->e_shentsize * idx));
}

int elf_mapped_size(void *elf, size_t *msize) {
	struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

	// check magic
	if (memcmp(ehdr->e_ident, ElfMagic, 4)) {
		return 1;
	}

	size_t s = 0;

	struct Elf64_Phdr *phdr = elf_pheader(ehdr);
	if (phdr) {
		// use segments
		for (int i = 0; i < ehdr->e_phnum; i++) {
			struct Elf64_Phdr *phdr = elf_segment(ehdr, i);

			uint64_t delta = phdr->p_paddr + phdr->p_memsz;
			if (delta > s) {
				s = delta;
			}
		}
	} else {
		// use sections
		for (int i = 0; i < ehdr->e_shnum; i++) {
			struct Elf64_Shdr *shdr = elf_section(ehdr, i);

			uint64_t delta = shdr->sh_addr + shdr->sh_size;
			if (delta > s) {
				s = delta;
			}
		}
	}

	if (msize) {
		*msize = s;
	}

	return 0;
}

int proc_map_elf(struct proc *p, void *elf, void *exec) {
	struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

	struct Elf64_Phdr *phdr = elf_pheader(ehdr);
	if (phdr) {
		// use segments
		for (int i = 0; i < ehdr->e_phnum; i++) {
			struct Elf64_Phdr *phdr = elf_segment(ehdr, i);

			if (phdr->p_filesz) {
				//memcpy((uint8_t *)exec + phdr->p_paddr, (uint8_t *)elf + phdr->p_offset, phdr->p_filesz);

				proc_write_mem(p, (void *)((uint8_t *)exec + phdr->p_paddr), phdr->p_filesz, (void *)((uint8_t *)elf + phdr->p_offset), NULL);
			}

			/*if (phdr->p_memsz - phdr->p_filesz) {
				memset((uint8_t *)exec + phdr->p_paddr + phdr->p_filesz, NULL, phdr->p_memsz - phdr->p_filesz);
			}*/
		}
	} else {
		// use sections
		for (int i = 0; i < ehdr->e_shnum; i++) {
			struct Elf64_Shdr *shdr = elf_section(ehdr, i);

			if (!(shdr->sh_flags & SHF_ALLOC)) {
				continue;
			}

			if (shdr->sh_size) {
				//memcpy((uint8_t *)exec + shdr->sh_addr, (uint8_t *)elf + shdr->sh_offset, shdr->sh_size);

				proc_write_mem(p, (void *)((uint8_t *)exec + shdr->sh_addr), shdr->sh_size, (void *)((uint8_t *)elf + shdr->sh_offset), NULL);
			}
		}
	}

	return 0;
}

int proc_relocate_elf(struct proc *p, void *elf, void *exec) {
	struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

	for (int i = 0; i < ehdr->e_shnum; i++) {
		struct Elf64_Shdr *shdr = elf_section(ehdr, i);

		// check table
		if (shdr->sh_type == SHT_REL) {
			// process each entry in the table
			for (int j = 0; j < shdr->sh_size / shdr->sh_entsize; j++) {
				struct Elf64_Rela *reltab = &((struct Elf64_Rela *)((uint64_t)ehdr + shdr->sh_offset))[j];
				uint8_t **ref = (uint8_t **)((uint8_t *)exec + reltab->r_offset);
				uint8_t *value = NULL;

				switch (ELF64_R_TYPE(reltab->r_info)) {
				case R_X86_64_RELATIVE:
					// *ref = (uint8_t *)exec + reltab->r_addend;
					value = (uint8_t *)exec + reltab->r_addend;
					proc_write_mem(p, ref, sizeof(value), (void *)&value, NULL);
					break;
				case R_X86_64_64:
				case R_X86_64_JUMP_SLOT:
				case R_X86_64_GLOB_DAT:
					// TODO: relocations
					break;
				}
			}
		}
	}

	return 0;
}

int rpc_proc_map_elf(struct proc *p, void *elf, uint64_t *elfbase, uint64_t *entry) {
	void *elfaddr = NULL;
	size_t msize = 0;
	int r = 0;

	struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

	r = elf_mapped_size(elf, &msize);
	if (r) {
		goto error;
	}

	// resize to pages
	msize += (PAGE_SIZE - (msize % PAGE_SIZE));

	// allocate
	r = proc_allocate(p, &elfaddr, msize);
	if (r) {
		goto error;
	}

	// map
	r = proc_map_elf(p, elf, elfaddr);
	if (r) {
		goto error;
	}

	// relocate
	r = proc_relocate_elf(p, elf, elfaddr);
	if (r) {
		goto error;
	}

	if (elfbase) {
		*elfbase = (uint64_t)elfaddr;
	}

	if (entry) {
		*entry = (uint64_t)elfaddr + ehdr->e_entry;
	}

error:
	return r;
}

int rpc_send_data(int fd, void *data, int length) {
	uint32_t left = length;
	uint32_t offset = 0;
	uint32_t sent = 0;

	while (left > 0) {
		if (left > RPC_MAX_DATA_LEN) {
			sent = net_send(fd, data + offset, RPC_MAX_DATA_LEN);
		} else {
			sent = net_send(fd, data + offset, left);
		}

		if (!sent && !net_errno) {
			return 0;
		}

		offset += sent;
		left -= sent;
	}

	return offset;
}

int rpc_recv_data(int fd, void *data, int length, int force) {
	uint32_t left = length;
	uint32_t offset = 0;
	uint32_t recv = 0;

	while (left > 0) {
		if (left > RPC_MAX_DATA_LEN) {
			recv = net_recv(fd, data + offset, RPC_MAX_DATA_LEN);
		} else {
			recv = net_recv(fd, data + offset, left);
		}

		if (!recv) {
			if (!net_errno) {
				return 0;
			}

			if (!force) {
				return offset;
			}
		}

		offset += recv;
		left -= recv;
	}

	return offset;
}

int rpc_send_status(int fd, uint32_t status) {
	uint32_t d = status;
	if (rpc_send_data(fd, &d, sizeof(uint32_t)) == sizeof(uint32_t)) {
		return 0;
	} else {
		return 1;
	}
}

int rpc_handle_read(int fd, struct rpc_proc_read *pread) {
	uint8_t *data = NULL;
	size_t n = 0;
	int r = 0;

	int length = pread->length;
	uint32_t left = length;
	uint32_t offset = 0;

	struct proc *p = proc_find_by_pid(pread->pid);
	if (p) {
		// test read
		uint8_t test = 0;
		r = proc_read_mem(p, (void *)pread->address, 1, &test, &n);
		if (r) {
			rpc_send_status(fd, RPC_READ_ERROR);
			r = 1;
			goto error;
		}

		rpc_send_status(fd, RPC_SUCCESS);
		if (net_errno) {
			goto error;
		}

		data = (uint8_t *)alloc(RPC_MAX_DATA_LEN);

		while (left) {
			uint32_t read = left;
			if (left > RPC_MAX_DATA_LEN) {
				read = RPC_MAX_DATA_LEN;
			}

			r = proc_read_mem(p, (void *)(pread->address + offset), (size_t)read, data, &n);
			if (r) {
				r = 1;
				goto error;
			} else {
				// send back data
				r = rpc_send_data(fd, data, read);
				if (!r) {
					r = 1;
					goto error;
				}
			}

			left -= read;
			offset += read;
		}
	} else {
		rpc_send_status(fd, RPC_NO_PROC);
		r = 1;
		goto error;
	}

error:
	if (data) {
		dealloc(data);
	}

	return r;
}

int rpc_handle_write(int fd, struct rpc_proc_write *pwrite) {
	uint8_t *data = NULL;
	size_t n = 0;
	int r = 0;

	int length = pwrite->length;

	struct proc *p = proc_find_by_pid(pwrite->pid);
	if (p) {
		if (length > RPC_MAX_DATA_LEN) {
			rpc_send_status(fd, RPC_TOO_MUCH_DATA);
			r = 1;
			goto error;
		}

		rpc_send_status(fd, RPC_SUCCESS);
		if (net_errno) {
			goto error;
		}

		data = (uint8_t *)alloc(length);
		rpc_recv_data(fd, data, length, 1);
		if (net_errno) {
			goto error;
		}

		r = proc_write_mem(p, (void *)pwrite->address, (size_t)length, data, &n);
		if (r || n != length) {
			rpc_send_status(fd, RPC_WRITE_ERROR);
			r = 1;
			goto error;
		} else {
			rpc_send_status(fd, RPC_SUCCESS);
		}
	} else {
		rpc_send_status(fd, RPC_NO_PROC);
		r = 1;
		goto error;
	}

error:
	if (data) {
		dealloc(data);
	}

	return 0;
}

int rpc_handle_list(int fd, struct rpc_packet *packet) {
	uint8_t *data = NULL;
	uint32_t count = 0;
	uint32_t size = 0;
	int r = 0;

	uint64_t kernbase = getkernbase();
	struct proc *p = *(struct proc **)(kernbase + __allproc);

	struct proc *countp = p;
	do {
		count++;
	} while ((countp = countp->p_forw));

	if (!count) {
		rpc_send_status(fd, RPC_LIST_ERROR);
		r = 1;
		goto error;
	}

	size = count * RPC_PROC_LIST_SIZE;
	data = (uint8_t *)alloc(size);
	if (!data) {
		rpc_send_status(fd, RPC_LIST_ERROR);
		r = 1;
		goto error;
	}

	struct rpc_proc_list *plist = (struct rpc_proc_list *)data;
	for (int i = 0; i < count; i++) {
		memcpy(plist[i].name, p->p_comm, sizeof(plist[i].name));
		plist[i].pid = p->pid;

		if (!(p = p->p_forw)) {
			break;
		}
	}

	rpc_send_status(fd, RPC_SUCCESS);
	if (net_errno) {
		goto error;
	}

	rpc_send_data(fd, &count, sizeof(uint32_t));
	if (net_errno) {
		goto error;
	}

	rpc_send_data(fd, data, size);
	if (net_errno) {
		goto error;
	}

error:
	if (data) {
		dealloc(data);
	}

	return r;
}

int rpc_handle_info(int fd, struct rpc_proc_info1 *pinfo) {
	struct proc_vm_map_entry *entries = NULL;
	size_t num_entries = 0;
	uint32_t count = 0;
	uint32_t size = 0;
	uint8_t *data = NULL;
	int r = 0;

	struct proc *p = proc_find_by_pid(pinfo->pid);
	if (!p) {
		rpc_send_status(fd, RPC_NO_PROC);
		r = 1;
		goto error;
	}

	r = proc_get_vm_map(p, &entries, &num_entries);
	count = num_entries;
	if (r) {
		rpc_send_status(fd, RPC_INFO_ERROR);
		r = 1;
		goto error;
	}

	// some processes, like daemons do not have any virtual memory mapped
	if (!count) {
		rpc_send_status(fd, RPC_INFO_NO_MAP);
		r = 0;
		goto error;
	}

	size = count * RPC_PROC_INFO2_SIZE;
	data = (uint8_t *)alloc(size);
	if (!data) {
		rpc_send_status(fd, RPC_INFO_ERROR);
		r = 1;
		goto error;
	}

	struct rpc_proc_info2 *info = (struct rpc_proc_info2 *)data;
	for (int i = 0; i < count; i++) {
		memcpy(info[i].name, entries[i].name, sizeof(info[i].name));
		info[i].start = entries[i].start;
		info[i].end = entries[i].end;
		info[i].offset = entries[i].offset;
		info[i].prot = entries[i].prot;
	}

	rpc_send_status(fd, RPC_SUCCESS);
	if (net_errno) {
		goto error;
	}

	rpc_send_data(fd, &count, sizeof(uint32_t));
	if (net_errno) {
		goto error;
	}

	rpc_send_data(fd, data, size);
	if (net_errno) {
		goto error;
	}

error:
	if (data) {
		dealloc(data);
	}

	if (entries) {
		dealloc(entries);
	}

	return r;
}

int rpc_handle_install(int fd, struct rpc_proc_install1 *pinstall) {
	void *stubaddr = NULL;
	size_t n = 0;
	int r = 0;

	uint64_t stubsize = sizeof(rpcstub);
	stubsize += (PAGE_SIZE - (stubsize % PAGE_SIZE));

	struct proc *p = proc_find_by_pid(pinstall->pid);
	if (p) {
		// allocate stub
		r = proc_allocate(p, &stubaddr, stubsize);
		if (r) {
			rpc_send_status(fd, RPC_INSTALL_ERROR);
			goto error;
		}

		// write stub
		r = proc_write_mem(p, stubaddr, sizeof(rpcstub), (void *)rpcstub, &n);
		if (r) {
			rpc_send_status(fd, RPC_INSTALL_ERROR);
			goto error;
		}

		// load stub
		uint64_t stubentryaddr = (uint64_t)stubaddr + *(uint64_t *)(rpcstub + 4);
		if (rpc_proc_load(p, stubentryaddr)) {
			rpc_send_status(fd, RPC_INSTALL_ERROR);
			r = 1;
			goto error;
		}

		struct rpc_proc_install2 data;
		data.pid = pinstall->pid;
		data.rpcstub = (uint64_t)stubaddr;

		rpc_send_status(fd, RPC_SUCCESS);
		if (net_errno) {
			goto error;
		}

		rpc_send_data(fd, &data, RPC_PROC_INSTALL2_SIZE);
		if (net_errno) {
			goto error;
		}
	} else {
		rpc_send_status(fd, RPC_NO_PROC);
		r = 1;
		goto error;
	}

error:
	return r;
}

int rpc_handle_call(int fd, struct rpc_proc_call1 *pcall) {
	size_t n = 0;
	int r = 0;

	uint64_t rpcstub = pcall->rpcstub;

	struct proc *p = proc_find_by_pid(pcall->pid);
	if (p) {
		// write registers
		// these two structures are basically 1:1 (it is hackey but meh)
		size_t regsize = offsetof(struct rpcstub_header, rpc_rax) - offsetof(struct rpcstub_header, rpc_rip);
		r = proc_write_mem(p, (void *)(rpcstub + offsetof(struct rpcstub_header, rpc_rip)), regsize, &pcall->rpc_rip, &n);
		if (r) {
			rpc_send_status(fd, RPC_CALL_ERROR);
			r = 1;
			goto error;
		}

		// trigger call
		uint8_t rpc_go = 1;
		r = proc_write_mem(p, (void *)(rpcstub + offsetof(struct rpcstub_header, rpc_go)), sizeof(rpc_go), &rpc_go, &n);
		if (r) {
			rpc_send_status(fd, RPC_CALL_ERROR);
			r = 1;
			goto error;
		}

		// check until done
		uint8_t rpc_done = 0;
		while (!rpc_done) {
			r = proc_read_mem(p, (void *)(rpcstub + offsetof(struct rpcstub_header, rpc_done)), sizeof(rpc_done), &rpc_done, &n);
			if (r) {
				rpc_send_status(fd, RPC_CALL_ERROR);
				r = 1;
				goto error;
			}
		}

		// write done
		rpc_done = 0;
		r = proc_write_mem(p, (void *)(rpcstub + offsetof(struct rpcstub_header, rpc_done)), sizeof(rpc_done), &rpc_done, &n);
		if (r) {
			rpc_send_status(fd, RPC_CALL_ERROR);
			r = 1;
			goto error;
		}

		// return value
		uint64_t rpc_rax = 0;
		r = proc_read_mem(p, (void *)(rpcstub + offsetof(struct rpcstub_header, rpc_rax)), sizeof(rpc_rax), &rpc_rax, &n);
		if (r) {
			rpc_send_status(fd, RPC_CALL_ERROR);
			r = 1;
			goto error;
		}

		struct rpc_proc_call2 data;
		data.pid = pcall->pid;
		data.rpc_rax = rpc_rax;

		rpc_send_status(fd, RPC_SUCCESS);
		if (net_errno) {
			goto error;
		}

		rpc_send_data(fd, &data, RPC_PROC_CALL2_SIZE);
		if (net_errno) {
			goto error;
		}
	} else {
		rpc_send_status(fd, RPC_NO_PROC);
		r = 1;
		goto error;
	}

error:
	return r;
}

int rpc_handle_elf(int fd, struct rpc_proc_elf *pelf) {
	struct proc_vm_map_entry *entries = NULL;
	size_t num_entries = 0;
	uint8_t *data = NULL;
	int r = 0;

	struct proc *p = proc_find_by_pid(pelf->pid);
	if (p) {
		// allocate
		data = (uint8_t *)alloc(pelf->size);
		if (!data) {
			rpc_send_status(fd, RPC_ELF_ERROR);
			r = 1;
			goto error;
		}

		// recv the elf
		rpc_recv_data(fd, data, pelf->size, 1);
		if (net_errno) {
			goto error;
		}

		// map the elf
		// int rpc_proc_map_elf(struct proc *p, void *elf, uint64_t *elfbase, uint64_t *entry)
		uint64_t entry = 0;
		r = rpc_proc_map_elf(p, data, NULL, &entry);
		if (r) {
			rpc_send_status(fd, RPC_ELF_ERROR);
			goto error;
		}

		// change main executable protection to rwx
		r = proc_get_vm_map(p, &entries, &num_entries);
		if (r) {
			rpc_send_status(fd, RPC_ELF_ERROR);
			r = 1;
			goto error;
		}

		for (int i = 0; i < num_entries; i++) {
			if (entries[i].prot != (PROT_READ | PROT_EXEC)) {
				continue;
			}

			if (!memcmp(entries[i].name, "executable", 10)) {
				proc_mprotect(p, (void *)entries[i].start, (void *)entries[i].end, VM_PROT_ALL);
				break;
			}
		}

		// call loader
		if (rpc_proc_load(p, entry)) {
			rpc_send_status(fd, RPC_ELF_ERROR);
			r = 1;
			goto error;
		}

		rpc_send_status(fd, RPC_SUCCESS);
	} else {
		rpc_send_status(fd, RPC_NO_PROC);
		r = 1;
		goto error;
	}

error:
	if (entries) {
		dealloc(entries);
	}

	if (data) {
		dealloc(data);
	}

	return r;
}

int rpc_handle_kbase(int fd, struct rpc_packet *packet) {
	int r = 0;

	uint64_t kernbase = getkernbase();

	rpc_send_status(fd, RPC_SUCCESS);
	if (net_errno) {
		goto error;
	}

	rpc_send_data(fd, &kernbase, RPC_KERN_BASE_SIZE);
	if (net_errno) {
		goto error;
	}

error:
	return r;
}

int rpc_handle_kread(int fd, struct rpc_kern_read *pread) {
	uint8_t *data = NULL;
	int r = 0;

	int length = pread->length;
	uint32_t left = length;
	uint32_t offset = 0;

	rpc_send_status(fd, RPC_SUCCESS);
	if (net_errno) {
		goto error;
	}

	data = (uint8_t *)alloc(RPC_MAX_DATA_LEN);

	while (left) {
		uint32_t read = left;
		if (left > RPC_MAX_DATA_LEN) {
			read = RPC_MAX_DATA_LEN;
		}

		memcpy(data, (void *)(pread->address + offset), (size_t)read);

		// send back data
		r = rpc_send_data(fd, data, read);
		if (!r) {
			r = 1;
			goto error;
		}

		left -= read;
		offset += read;
	}

error:
	if (data) {
		dealloc(data);
	}

	return r;
}

int rpc_handle_kwrite(int fd, struct rpc_kern_write *pwrite) {
	uint8_t *data = NULL;
	int r = 0;

	int length = pwrite->length;

	if (length > RPC_MAX_DATA_LEN) {
		rpc_send_status(fd, RPC_TOO_MUCH_DATA);
		r = 1;
		goto error;
	}

	rpc_send_status(fd, RPC_SUCCESS);
	if (net_errno) {
		goto error;
	}

	data = (uint8_t *)alloc(length);
	rpc_recv_data(fd, data, length, 1);
	if (net_errno) {
		goto error;
	}

	uint64_t CR0 = __readcr0();
	__writecr0(CR0 & ~CR0_WP);

	memcpy((void *)pwrite->address, data, (size_t)length);

	__writecr0(CR0);

	rpc_send_status(fd, RPC_SUCCESS);

error:
	if (data) {
		dealloc(data);
	}

	return r;
}

int rpc_cmd_handler(int fd, struct rpc_packet *packet) {
	//uprintf("packet cmd %X\n", packet->cmd);

	if (!RPC_VALID_CMD(packet->cmd)) {
		return 1;
	}

	switch (packet->cmd) {
	case RPC_PROC_READ: {
		rpc_handle_read(fd, (struct rpc_proc_read *)packet->data);
		break;
	}
	case RPC_PROC_WRITE: {
		rpc_handle_write(fd, (struct rpc_proc_write *)packet->data);
		break;
	}
	case RPC_PROC_LIST: {
		rpc_handle_list(fd, NULL);
		break;
	}
	case RPC_PROC_INFO: {
		rpc_handle_info(fd, (struct rpc_proc_info1 *)packet->data);
		break;
	}
	case RPC_PROC_INTALL: {
		rpc_handle_install(fd, (struct rpc_proc_install1 *)packet->data);
		break;
	}
	case RPC_PROC_CALL: {
		rpc_handle_call(fd, (struct rpc_proc_call1 *)packet->data);
		break;
	}
	case RPC_PROC_ELF: {
		rpc_handle_elf(fd, (struct rpc_proc_elf *)packet->data);
		break;
	}
	case RPC_END: {
		return 1;
		break;
	}
	case RPC_REBOOT: {
		kern_reboot(0);
		break;
	}
	case RPC_KERN_BASE: {
		rpc_handle_kbase(fd, NULL);
		break;
	}
	case RPC_KERN_READ: {
		rpc_handle_kread(fd, (struct rpc_kern_read *)packet->data);
		break;
	}
	case RPC_KERN_WRITE: {
		rpc_handle_kwrite(fd, (struct rpc_kern_write *)packet->data);
		break;
	}
	}

	return 0;
}

void rpc_handler(void *vfd) {
	int fd = (uint64_t)vfd;
	struct rpc_packet packet;
	uint8_t *data = NULL;
	uint32_t length = 0;
	int r = 0;

	kthread_set_affinity("rpchandler", 150, 0x400, 0);

	while (1) {
		kthread_suspend_check();

		pause("rpchandler", 15);

		// wait to recv packets
		r = rpc_recv_data(fd, &packet, RPC_PACKET_SIZE, 0);

		if (!r) {
			// check if disconnected
			if (net_errno == 0) {
				goto error;
			}

			continue;
		}

		// invalid packet
		if (packet.magic != RPC_PACKET_MAGIC) {
			continue;
		}

		// mismatch received size
		if (r != RPC_PACKET_SIZE) {
			continue;
		}

		length = packet.datalen;
		if (length) {
			// check
			if (length > RPC_MAX_DATA_LEN) {
				continue;
			}

			// allocate data
			data = (uint8_t *)alloc(length);
			if (!data) {
				goto error;
			}

			// recv data
			r = rpc_recv_data(fd, data, length, 1);
			if (!r) {
				goto error;
			}

			// set data
			packet.data = data;
		} else {
			packet.data = NULL;
		}

		// handle the packet
		r = rpc_cmd_handler(fd, &packet);

		if (data) {
			dealloc(data);
			data = NULL;
		}

		// check cmd handler error (or end cmd)
		if (r) {
			goto error;
		}
	}

error:
	net_close(fd);
	kthread_exit();
}

void rpc_server_thread(void *arg) {
	struct sockaddr_in servaddr;
	int fd = -1;
	int newfd = -1;
	int r = 0;

	kthread_set_affinity("rpcserver", 175, 0x400, 0);

	fd = net_socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		goto error;
	}

	// set it to not generate SIGPIPE
	int optval = 1;
	net_setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&optval, sizeof(int));

	// non blocking socket
	optval = 1;
	net_setsockopt(fd, SOL_SOCKET, SO_NBIO, (void *)&optval, sizeof(int));

	// no delay to merge packets
	optval = 1;
	net_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&optval, sizeof(int));

	memset(&servaddr, NULL, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(RPC_PORT);

	if ((r = net_bind(fd, (struct sockaddr *)&servaddr, sizeof(servaddr)))) {
		goto error;
	}

	if ((r = net_listen(fd, 8))) {
		goto error;
	}
	
	while (1) {
		kthread_suspend_check();

		// accept connection
		newfd = net_accept(fd, NULL, NULL);

		if (newfd > -1 && !net_errno) {
			// set it to not generate SIGPIPE
			int optval = 1;
			net_setsockopt(newfd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&optval, sizeof(int));

			// non blocking socket
			optval = 1;
			net_setsockopt(newfd, SOL_SOCKET, SO_NBIO, (void *)&optval, sizeof(int));

			// no delay to merge packets
			optval = 1;
			net_setsockopt(newfd, IPPROTO_TCP, TCP_NODELAY, (void *)&optval, sizeof(int));

			// add thread to handle connection
			kproc_kthread_add(rpc_handler, (void *)((uint64_t)newfd), &krpcproc, NULL, NULL, 0, "rpcproc", "rpchandler");
		}

		pause("rpcserver", 80);
	}

error:
	net_close(fd);
	kthread_exit();
}

void init_rpc() {
	net_disable_copy_checks();

	kproc_create(rpc_server_thread, NULL, &krpcproc, NULL, 0, "rpcproc");

	uprintf("[jkpatch] started rpc server!");
}
