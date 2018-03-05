/* golden */
/* 2/1/2018 */

#include "net.h"

// todo: add offsets to magic, or parse sysent table

int net_errno;

// specific to 4.55, may change in other updates
// the kernel functions copyin and copyout check if the src/dst address is in kernel space
void net_disable_copy_checks() {
	uint64_t kernbase = getkernbase();
	uint64_t CR0 = __readcr0();

	uint16_t *copyin1 = (uint16_t *)(kernbase + 0x14A8D8);
	uint16_t *copyin2 = (uint16_t *)(kernbase + 0x14A8E7);

	uint16_t *copyout1 = (uint16_t *)(kernbase + 0x14A7EB);
	uint16_t *copyout2 = (uint16_t *)(kernbase + 0x14A7F3);
	uint16_t *copyout3 = (uint16_t *)(kernbase + 0x14A802);

	__writecr0(CR0 & ~CR0_WP);
	*copyin1 = 0x9090;
	*copyin2 = 0x9090;
	*copyout1 = 0x9090;
	*copyout2 = 0x9090;
	*copyout3 = 0x9090;
	__writecr0(CR0);
}

void net_enable_copy_checks() {
	uint64_t kernbase = getkernbase();
	uint64_t CR0 = __readcr0();

	uint16_t *copyin1 = (uint16_t *)(kernbase + 0x14A8D8);
	uint16_t *copyin2 = (uint16_t *)(kernbase + 0x14A8E7);

	uint16_t *copyout1 = (uint16_t *)(kernbase + 0x14A7EB);
	uint16_t *copyout2 = (uint16_t *)(kernbase + 0x14A7F3);
	uint16_t *copyout3 = (uint16_t *)(kernbase + 0x14A802);

	__writecr0(CR0 & ~CR0_WP);
	*copyin1 = 0x4672;
	*copyin2 = 0x3777;
	*copyout1 = 0x6375;
	*copyout2 = 0x5B72;
	*copyout3 = 0x4C77;
	__writecr0(CR0);
}

int net_socket(int domain, int type, int protocol) {
	struct sys_socket_args {
		uint64_t domain;
		uint64_t type;
		uint64_t protocol;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_socket)(struct thread * td, struct sys_socket_args * uap) = (void *)(kernbase + 0x3EAC20);

	struct thread *td = curthread();

	struct sys_socket_args uap;
	uap.domain = domain;
	uap.type = type;
	uap.protocol = protocol;

	net_errno = sys_socket(td, &uap);

	return td->td_retval[0];
}

int net_bind(int sockfd, struct sockaddr *addr, int addrlen) {
	struct sys_bind_args {
		uint64_t sockfd;
		uint64_t name;
		uint64_t namelen;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_bind)(struct thread * td, struct sys_bind_args * uap) = (void *)(kernbase + 0x3EB550);

	struct thread *td = curthread();

	struct sys_bind_args uap;
	uap.sockfd = sockfd;
	uap.name = (uint64_t)addr;
	uap.namelen = addrlen;

	net_errno = sys_bind(td, &uap);

	return net_errno;
}

int net_listen(int sockfd, int backlog) {
	struct sys_listen_args {
		uint64_t sockfd;
		uint64_t backlog;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_listen)(struct thread * td, struct sys_listen_args * uap) = (void *)(kernbase + 0x3EB760);

	struct thread *td = curthread();

	struct sys_listen_args uap;
	uap.sockfd = sockfd;
	uap.backlog = backlog;

	net_errno = sys_listen(td, &uap);

	return net_errno;
}

int net_accept(int sockfd, struct sockaddr *addr, int *addrlen) {
	struct sys_accept_args {
		uint64_t sockfd;
		uint64_t name;
		uint64_t namelen;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_accept)(struct thread * td, struct sys_accept_args * uap) = (void *)(kernbase + 0x3EBEC0);

	struct thread *td = curthread();

	struct sys_accept_args uap;
	uap.sockfd = sockfd;
	uap.name = (uint64_t)addr;
	uap.namelen = (uint64_t)addrlen;

	net_errno = sys_accept(td, &uap);

	return td->td_retval[0];
}

int net_recv(int fd, void *buf, uint64_t len) {
	struct sys_read_args {
		uint64_t fd;
		uint64_t buf;
		uint64_t nbyte;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_read)(struct thread * td, struct sys_read_args * uap) = (void *)(kernbase + 0x5EC50);

	struct thread *td = curthread();

	struct sys_read_args uap;
	uap.fd = fd;
	uap.buf = (uint64_t)buf;
	uap.nbyte = len;

	net_errno = sys_read(td, &uap);

	return td->td_retval[0];
}

int net_send(int fd, const void *buf, uint64_t len) {
	struct sys_write_args {
		uint64_t fd;
		uint64_t buf;
		uint64_t nbyte;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_write)(struct thread * td, struct sys_write_args * uap) = (void *)(kernbase + 0x5F1A0);

	struct thread *td = curthread();

	struct sys_write_args uap;
	uap.fd = fd;
	uap.buf = (uint64_t)buf;
	uap.nbyte = len;

	net_errno = sys_write(td, &uap);

	return td->td_retval[0];
}

int net_setsockopt(int s, int level, int optname, const void *optval, uint32_t optlen) {
	struct sys_setsockopt_args {
		uint64_t fd;
		uint64_t level;
		uint64_t optname;
		uint64_t optval;
		uint64_t optlen;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_setsockopt)(struct thread * td, struct sys_setsockopt_args * uap) = (void *)(kernbase + 0x3ED300);

	struct thread *td = curthread();

	struct sys_setsockopt_args uap;
	uap.fd = s;
	uap.level = level;
	uap.optname = optname;
	uap.optval = (uint64_t)optval;
	uap.optlen = optlen;

	net_errno = sys_setsockopt(td, &uap);

	return net_errno;
}

int net_close(int fd) {
	struct sys_close_args {
		uint64_t fd;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_close)(struct thread * td, struct sys_close_args * uap) = (void *)(kernbase + 0x42AC00);

	struct thread *td = curthread();

	struct sys_close_args uap;
	uap.fd = fd;

	net_errno = sys_close(td, &uap);

	return net_errno;
}
