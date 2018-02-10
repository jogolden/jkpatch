/* golden */
/* 2/1/2018 */

#include "rpc.h"

int rpc_send_status(int fd, uint32_t status) {
	uint32_t d = status;
	if (net_send(fd, &d, sizeof(uint32_t)) == sizeof(uint32_t)) {
		return 0;
	} else {
		return 1;
	}
}

int rpc_send_data(int fd, uint8_t *data, int length) {
	uint32_t left = length;
	uint32_t offset = 0;
	uint32_t sent = 0;

	while (left > 0) {
		if (left > RPC_MAX_DATA_LEN) {
			sent = net_send(fd, data + offset, RPC_MAX_DATA_LEN);
			offset += sent;
			left -= sent;
		} else {
			sent = net_send(fd, data + offset, left);
			offset += sent;
			left -= sent;
		}
	}

	return 0;
}

int rpc_handle_read(int fd, struct rpc_packet *packet) {
	uint8_t *data = NULL;
	size_t n = 0;
	int r = 0;

	struct rpc_proc_read *pread = (struct rpc_proc_read *)packet->data;

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
			goto error;
		} else {
			// send back data
			rpc_send_status(fd, RPC_SUCCESS);
			net_send(fd, data, length);
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

int rpc_handle_write(int fd, struct rpc_packet *packet) {
	uint8_t *data = NULL;
	size_t n = 0;
	int r = 0;

	struct rpc_proc_read *pwrite = (struct rpc_proc_read *)packet->data;

	int length = pwrite->length;

	struct proc *p = proc_find_by_pid(pwrite->pid);
	if (p) {
		if (length > RPC_MAX_DATA_LEN) {
			rpc_send_status(fd, RPC_TOO_MUCH_DATA);
			r = 1;
			goto error;
		}

		rpc_send_status(fd, RPC_SUCCESS);

		data = (uint8_t *)alloc(length);
		net_recv(fd, data, length);

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

	for (int i = 0; i < count; i++) {
		struct rpc_proc_list *plist = (struct rpc_proc_list *)(data + (i * RPC_PROC_LIST_SIZE));

		memcpy(plist->name, p->p_comm, sizeof(plist->name));
		plist->pid = p->pid;

		if (!(p = p->p_forw)) {
			break;
		}
	}

	rpc_send_status(fd, RPC_SUCCESS);
	net_send(fd, &count, sizeof(uint32_t));
	rpc_send_data(fd, data, size);

error:
	if (data) {
		dealloc(data);
	}

	return r;
}

int rpc_handle_info(int fd, struct rpc_packet *packet) {
	struct proc_vm_map_entry *entries = NULL;
	size_t num_entries = 0;
	uint32_t count = 0;
	uint32_t size = 0;
	uint8_t *data = NULL;
	int r = 0;

	struct rpc_proc_info1 *pinfo = (struct rpc_proc_info1 *)packet->data;
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

	for (int i = 0; i < count; i++) {
		struct rpc_proc_info2 *info = (struct rpc_proc_info2 *)(data + (i * RPC_PROC_INFO2_SIZE));

		memcpy(info->name, entries[i].name, sizeof(info->name));
		info->start = entries[i].start;
		info->end = entries[i].end;
		info->offset = entries[i].offset;
		info->prot = entries[i].prot;
	}

	rpc_send_status(fd, RPC_SUCCESS);
	net_send(fd, &count, sizeof(uint32_t));
	rpc_send_data(fd, data, size);

error:
	if (data) {
		dealloc(data);
	}

	if (entries) {
		dealloc(entries);
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
		rpc_handle_read(fd, packet);
		break;
	}
	case RPC_PROC_WRITE: {
		rpc_handle_write(fd, packet);
		break;
	}
	case RPC_PROC_LIST: {
		rpc_handle_list(fd, packet);
		break;
	}
	case RPC_PROC_INFO: {
		rpc_handle_info(fd, packet);
		break;
	}
	case RPC_PROC_INTALL: {
		// todo
		break;
	}
	case RPC_PROC_CALL: {
		// todo
		break;
	}
	case RPC_PROC_END: {
		return 1;
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

	//uprintf("rpc_handler fd %lli", fd);

	while (1) {
		// wait to recv packets
		r = net_recv(fd, &packet, RPC_PACKET_SIZE);

		// check if disconnected
		if (r <= 0) {
			goto error;
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
			r = net_recv(fd, data, length);
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

		//pause("p", 15);
	}

error:
	if (fd > -1) {
		net_close(fd);
	}

	kthread_exit();
}

void rpc_server_thread(void *arg) {
	struct sockaddr_in servaddr;
	int fd = -1;
	int newfd = -1;
	int r = 0;

	fd = net_socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		goto error;
	}

	// set it to not generate SIGPIPE
	int optval = 1;
	net_setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&optval, sizeof(int));

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

	if ((r = net_listen(fd, 32))) {
		goto error;
	}

	while (1) {
		// accept connection
		newfd = net_accept(fd, NULL, NULL);

		// the socket will most likley inherit such properties below, but to make sure I will set them

		// set it to not generate SIGPIPE
		int optval = 1;
		net_setsockopt(newfd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&optval, sizeof(int));

		// no delay to merge packets
		optval = 1;
		net_setsockopt(newfd, IPPROTO_TCP, TCP_NODELAY, (void *)&optval, sizeof(int));

		// add thread to handle connection
		kthread_add(rpc_handler, (void *)((uint64_t)newfd), 0, 0, 0, 0, "rpchandler");

		pause("p", 1000);
	}
error:
	if (fd > -1) {
		net_close(fd);
	}

	kthread_exit();
}

void init_rpc() {
	kthread_add(rpc_server_thread, 0, 0, 0, 0, 0, "rpcserver");
	uprintf("[jkpatch] started rpc server!");
}
