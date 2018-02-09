/* golden */
/* 2/1/2018 */

#include "net.h"

// todo: add offsets to magic, or parse sysent table

// specific to 4.05, may change in other updates
// the kernel functions copyin and copyout check if the src/dst address is in kernel space
void disable_copy_checks() {
	uint64_t kernbase = getkernbase();
	uint64_t CR0 = __readcr0();

	uint16_t *copyin1 = (uint16_t *)(kernbase + 0x286E12);
	uint16_t *copyin2 = (uint16_t *)(kernbase + 0x286E21);

	uint16_t *copyout1 = (uint16_t *)(kernbase + 0x286D92);
	uint16_t *copyout2 = (uint16_t *)(kernbase + 0x286DA1);

	__writecr0(CR0 & ~CR0_WP);
	*copyin1 = 0x9090;
	*copyin2 = 0x9090;
	*copyout1 = 0x9090;
	*copyout2 = 0x9090;
	__writecr0(CR0);
}

void enable_copy_checks() {
	uint64_t kernbase = getkernbase();
	uint64_t CR0 = __readcr0();

	uint16_t *copyin1 = (uint16_t *)(kernbase + 0x286E12);
	uint16_t *copyin2 = (uint16_t *)(kernbase + 0x286E21);

	uint16_t *copyout1 = (uint16_t *)(kernbase + 0x286D92);
	uint16_t *copyout2 = (uint16_t *)(kernbase + 0x286DA1);

	__writecr0(CR0 & ~CR0_WP);
	*copyin1 = 0x3C72;
	*copyin2 = 0x2D77;
	*copyout1 = 0x3C72;
	*copyout2 = 0x2D77;
	__writecr0(CR0);
}

int net_socket(int domain, int type, int protocol) {
	struct sys_socket_args {
		uint64_t domain;
		uint64_t type;
		uint64_t protocol;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_socket)(struct thread * td, struct sys_socket_args * uap) = (void *)(kernbase + 0x121340);

	struct thread *td = curthread();

	struct sys_socket_args uap;
	uap.domain = domain;
	uap.type = type;
	uap.protocol = protocol;

	sys_socket(td, &uap);

	return td->td_retval[0];
}

int net_bind(int sockfd, struct sockaddr *addr, int addrlen) {
	struct sys_bind_args {
		uint64_t sockfd;
		uint64_t name;
		uint64_t namelen;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_bind)(struct thread * td, struct sys_bind_args * uap) = (void *)(kernbase + 0x121C80);

	struct thread *td = curthread();

	struct sys_bind_args uap;
	uap.sockfd = sockfd;
	uap.name = (uint64_t)addr;
	uap.namelen = addrlen;

	disable_copy_checks();
	int r = sys_bind(td, &uap);
	enable_copy_checks();

	return r;
}

int net_listen(int sockfd, int backlog) {
	struct sys_listen_args {
		uint64_t sockfd;
		uint64_t backlog;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_listen)(struct thread * td, struct sys_listen_args * uap) = (void *)(kernbase + 0x121E90);

	struct thread *td = curthread();

	struct sys_listen_args uap;
	uap.sockfd = sockfd;
	uap.backlog = backlog;

	int r = sys_listen(td, &uap);

	return r;
}

int net_accept(int sockfd, struct sockaddr *addr, int *addrlen) {
	struct sys_accept_args {
		uint64_t sockfd;
		uint64_t name;
		uint64_t namelen;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_accept)(struct thread * td, struct sys_accept_args * uap) = (void *)(kernbase + 0x122620);

	struct thread *td = curthread();

	struct sys_accept_args uap;
	uap.sockfd = sockfd;
	uap.name = (uint64_t)addr;
	uap.namelen = (uint64_t)addrlen;

	disable_copy_checks();
	sys_accept(td, &uap);
	enable_copy_checks();

	return td->td_retval[0];
}

int net_recv(int fd, void *buf, uint64_t len) {
	struct sys_read_args {
		uint64_t fd;
		uint64_t buf;
		uint64_t nbyte;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_read)(struct thread * td, struct sys_read_args * uap) = (void *)(kernbase + 0x166820);

	struct thread *td = curthread();

	struct sys_read_args uap;
	uap.fd = fd;
	uap.buf = (uint64_t)buf;
	uap.nbyte = len;

	disable_copy_checks();
	sys_read(td, &uap);
	enable_copy_checks();

	return td->td_retval[0];
}

int net_send(int fd, const void *buf, uint64_t len) {
	struct sys_write_args {
		uint64_t fd;
		uint64_t buf;
		uint64_t nbyte;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_write)(struct thread * td, struct sys_write_args * uap) = (void *)(kernbase + 0x166D70);

	struct thread *td = curthread();

	struct sys_write_args uap;
	uap.fd = fd;
	uap.buf = (uint64_t)buf;
	uap.nbyte = len;

	disable_copy_checks();
	sys_write(td, &uap);
	enable_copy_checks();

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

	int (*sys_setsockopt)(struct thread * td, struct sys_setsockopt_args * uap) = (void *)(kernbase + 0x123A90);

	struct thread *td = curthread();

	struct sys_setsockopt_args uap;
	uap.fd = s;
	uap.level = level;
	uap.optname = optname;
	uap.optval = (uint64_t)optval;
	uap.optlen = optlen;

	disable_copy_checks();
	int r = sys_setsockopt(td, &uap);
	enable_copy_checks();

	return r;
}

int net_close(int fd) {
	struct sys_close_args {
		uint64_t fd;
	};

	uint64_t kernbase = getkernbase();

	int (*sys_close)(struct thread * td, struct sys_close_args * uap) = (void *)(kernbase + 0x45C430);

	struct thread *td = curthread();

	struct sys_close_args uap;
	uap.fd = fd;

	return sys_close(td, &uap);
}
