/* golden */
/* 2/1/2018 */

#include "rpc.h"

struct proc *krpcproc;

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
			if (force) {
				pause("rpcrecvdata", 5);
			} else {
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

	struct proc *p = proc_find_by_pid(pread->pid);
	if (p) {
		if (length > RPC_MAX_DATA_LEN) {
			rpc_send_status(fd, RPC_TOO_MUCH_DATA);
			r = 1;
			goto error;
		}

		data = (uint8_t *)alloc(length);

		r = proc_read_mem(p, (void *)pread->address, (size_t)length, data, &n);
		if (r || n != length) {
			rpc_send_status(fd, RPC_READ_ERROR);
			r = 1;
			goto error;
		} else {
			// send back data
			rpc_send_status(fd, RPC_SUCCESS);
			rpc_send_data(fd, data, length);
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
	void *rpcldraddr = NULL;
	void *stubaddr = NULL;
	void *stackaddr = NULL;
	struct proc_vm_map_entry *entries = NULL;
	size_t num_entries = 0;
	size_t n = 0;
	int r = 0;

	struct proc *p = proc_find_by_pid(pinstall->pid);
	if (p) {
		// allocate rpc ldr
		uint64_t ldrsize = sizeof(rpcldr);
		ldrsize += (PAGE_SIZE - (ldrsize % PAGE_SIZE));
		r = proc_allocate(p, &rpcldraddr, ldrsize);
		if (r) {
			rpc_send_status(fd, RPC_INSTALL_ERROR);
			goto error;
		}

		// allocate rpc stub
		uint64_t stubsize = sizeof(rpcstub);
		stubsize += (PAGE_SIZE - (stubsize % PAGE_SIZE));
		r = proc_allocate(p, &stubaddr, stubsize);
		if (r) {
			rpc_send_status(fd, RPC_INSTALL_ERROR);
			goto error;
		}

		// allocate stack
		uint64_t stacksize = 0x8000;
		r = proc_allocate(p, &stackaddr, stacksize);
		if (r) {
			rpc_send_status(fd, RPC_INSTALL_ERROR);
			goto error;
		}

		// write loader
		r = proc_write_mem(p, rpcldraddr, sizeof(rpcldr), (void *)rpcldr, &n);
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

		// patch suword_lwpid
		// has a check to see if child_tid/parent_tid is in kernel memory, and it in so patch it
		uint64_t kernbase = getkernbase();
		uint64_t CR0 = __readcr0();
		uint16_t *suword_lwpid = (uint16_t *)(kernbase + 0x287074);
		__writecr0(CR0 & ~CR0_WP);
		*suword_lwpid = 0x9090;
		__writecr0(CR0);

		// donor thread
		struct thread *thr = TAILQ_FIRST(&p->p_threads);

		// find libkernel base
		r = proc_get_vm_map(p, &entries, &num_entries);
		if (r) {
			rpc_send_status(fd, RPC_INFO_ERROR);
			r = 1;
			goto error;
		}

		// offsets are for 4.05 libraries
		// todo: write patch finder

		// libkernel.sprx
		// 0x11570 scePthreadCreate
		// 0x7CD20 thr_initial
		// offset 0x6B7B0

		// libkernel_web.sprx
		// 0x11570 scePthreadCreate
		// 0x7CD20 thr_initial
		// offset 0x6B7B0

		// libkernel_sys.sprx
		// 0x120A0 scePthreadCreate
		// 0x80D20 thr_initial
		// offset 0x6EC80

		uint64_t _scePthreadCreate = 0, _thr_initial = 0;
		for (int i = 0; i < num_entries; i++) {
			if(entries[i].prot != (PROT_READ | PROT_EXEC)) {
				continue;
			}

			if (!memcmp(entries[i].name, "libkernel.sprx", 14) ||
			        !memcmp(entries[i].name, "libkernel_web.sprx", 18)) {
				_scePthreadCreate = entries[i].start + 0x11570;
				_thr_initial = entries[i].start + 0x7CD20;
				break;
			}

			if (!memcmp(entries[i].name, "libkernel_sys.sprx", 18)) {
				_scePthreadCreate = entries[i].start + 0x120A0;
				_thr_initial = entries[i].start + 0x80D20;
				break;
			}
		}

		if(!_scePthreadCreate || !_thr_initial) {
			rpc_send_status(fd, RPC_INFO_ERROR);
			r = 1;
			goto error;
		}

		// write variables
		uint64_t stubentryaddr = (uint64_t)stubaddr + *(uint64_t *)(rpcstub + 4);
		r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, stubentry), sizeof(stubentryaddr), (void *)&stubentryaddr, &n);
		if (r) {
			rpc_send_status(fd, RPC_INSTALL_ERROR);
			goto error;
		}

		r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadCreate), sizeof(_scePthreadCreate), (void *)&_scePthreadCreate, &n);
		if (r) {
			rpc_send_status(fd, RPC_INSTALL_ERROR);
			goto error;
		}

		r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, thr_initial), sizeof(_thr_initial), (void *)&_thr_initial, &n);
		if (r) {
			rpc_send_status(fd, RPC_INSTALL_ERROR);
			goto error;
		}

		// execute loader
		uint64_t ldrentryaddr = (uint64_t)rpcldraddr + *(uint64_t *)(rpcldr + 4);
		r = create_thread(thr, NULL, (void *)ldrentryaddr, NULL, stackaddr, 0x8000, NULL, NULL, NULL, 0, NULL);
		if (r) {
			rpc_send_status(fd, RPC_INSTALL_ERROR);
			goto error;
		}

		// wait until loader is done
		uint8_t ldrdone = 0;
		while (!ldrdone) {
			r = proc_read_mem(p, (void *)(rpcldraddr + offsetof(struct rpcldr_header, ldrdone)), sizeof(ldrdone), &ldrdone, &n);
			if (r) {
				rpc_send_status(fd, RPC_CALL_ERROR);
				r = 1;
				goto error;
			}
		}

		proc_deallocate(p, rpcldraddr, ldrsize);
		proc_deallocate(p, stackaddr, stacksize);

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
	if (entries) {
		dealloc(entries);
	}

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
	case RPC_END: {
		return 1;
		break;
	}
	case RPC_REBOOT: {
		kern_reboot(0);
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

	kthread_set_affinity("rpchandler", 160, 0x400);

	while (1) {
		kthread_suspend_check();

		pause("rpchandler", 30);

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

	kthread_set_affinity("rpcserver", 180, 0x400);

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

		pause("rpcserver", 100);
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
