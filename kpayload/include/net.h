/* golden */
/* 2/1/2018 */

#ifndef _NET_H
#define _NET_H

#include "jkpayload.h"

// kernel level networking wrapper

// domains
#define	AF_UNIX		1		/* standardized name for AF_LOCAL */
#define	AF_INET		2		/* internetwork: UDP, TCP, etc. */

// types
#define	SOCK_STREAM	1		/* stream socket */
#define	SOCK_DGRAM	2		/* datagram socket */
#define	SOCK_RAW	3		/* raw-protocol interface */
#define	SOCK_RDM	4		/* reliably-delivered message */
#define	SOCK_SEQPACKET	5		/* sequenced packet stream */

#define	IPPROTO_IP		0		/* dummy for IP */
#define	IPPROTO_ICMP	1		/* control message protocol */
#define	IPPROTO_TCP		6		/* tcp */
#define	IPPROTO_UDP		17		/* user datagram protocol */

#define	INADDR_ANY			(uint32_t)0x00000000
#define	INADDR_BROADCAST	(uint32_t)0xffffffff	/* must be masked */

#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define NTOHL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define htons(n) HTONS(n)
#define ntohs(n) NTOHS(n)

#define htonl(n) HTONL(n)
#define ntohl(n) NTOHL(n)

/*
 * Level number for (get/set)sockopt() to apply to socket itself.
 */
#define	SOL_SOCKET	0xffff		/* options for socket level */

/*
 * Option flags per-socket.
 */
#define	SO_DEBUG		0x0001		/* turn on debugging info recording */
#define	SO_ACCEPTCONN	0x0002		/* socket has had listen() */
#define	SO_REUSEADDR	0x0004		/* allow local address reuse */
#define	SO_KEEPALIVE	0x0008		/* keep connections alive */
#define	SO_DONTROUTE	0x0010		/* just use interface addresses */
#define	SO_BROADCAST	0x0020		/* permit sending of broadcast msgs */
#define	SO_USELOOPBACK	0x0040		/* bypass hardware when possible */
#define	SO_LINGER		0x0080		/* linger on close if data present */
#define	SO_OOBINLINE	0x0100		/* leave received OOB data in line */
#define	SO_REUSEPORT	0x0200		/* allow local address & port reuse */
#define	SO_TIMESTAMP	0x0400		/* timestamp received dgram traffic */
#define	SO_NOSIGPIPE	0x0800		/* no SIGPIPE from EPIPE */
#define	SO_ACCEPTFILTER	0x1000		/* there is an accept filter */
#define	SO_BINTIME		0x2000		/* timestamp received dgram traffic */
#define	SO_NO_OFFLOAD	0x4000		/* socket cannot be offloaded */
#define	SO_NO_DDP		0x8000		/* disable direct data placement */
#define SO_NBIO			0x1200

#define	SO_SNDBUF	0x1001		/* send buffer size */
#define	SO_RCVBUF	0x1002		/* receive buffer size */
#define	SO_SNDLOWAT	0x1003		/* send low-water mark */
#define	SO_RCVLOWAT	0x1004		/* receive low-water mark */
#define	SO_SNDTIMEO	0x1005		/* send timeout */
#define	SO_RCVTIMEO	0x1006		/* receive timeout */
#define	SO_ERROR	0x1007		/* get error status and clear */
#define	SO_TYPE		0x1008		/* get socket type */

#define TCP_NODELAY     1       /* don't delay send to coalesce packets */
#define TCP_MAXSEG      2       /* set maximum segment size */
#define TCP_NOPUSH      4       /* don't push last block of write */
#define TCP_NOOPT       8       /* don't use TCP options */
#define TCP_MD5SIG      16      /* use MD5 digests (RFC2385) */
#define TCP_INFO        32      /* retrieve tcp_info structure */
#define TCP_CONGESTION  64      /* get/set congestion control algorithm */
#define TCP_CCALGOOPT   65      /* get/set cc algorithm specific options */
#define TCP_KEEPINIT    128     /* N, time to establish connection */
#define TCP_KEEPIDLE    256     /* L,N,X start keeplives after this period */
#define TCP_KEEPINTVL   512     /* L,N interval between keepalives */
#define TCP_KEEPCNT     1024    /* L,N number of keepalives before close */
#define TCP_FASTOPEN    1025    /* enable TFO / was created via TFO */
#define TCP_PCAP_OUT    2048    /* number of output packets to keep */
#define TCP_PCAP_IN     4096    /* number of input packets to keep */
#define TCP_FUNCTION_BLK 8192   /* Set the tcp function pointers to the specified stack */

struct sockaddr {
	uint8_t sa_len;		/* total length */
	uint8_t sa_family;	/* address family */
	char sa_data[14];	/* actually longer; address value */
};

struct in_addr {
	uint32_t s_addr;
};

struct sockaddr_in {
	uint8_t	sin_len;
	uint8_t sin_family;
	uint16_t sin_port;
	struct in_addr sin_addr;
	char sin_zero[8];
};

// kernel networking is tedious in freebsd, I do not want to deal with all the so* functions (never mind accepting a new connection...)
// I plan on actually just calling the system calls themselves with current thread and structures filled out with proper arguments

extern int net_errno;

void net_disable_copy_checks();
void net_enable_copy_checks();
int net_socket(int domain, int type, int protocol);
int net_bind(int sockfd, struct sockaddr *addr, int addrlen);
int net_listen(int sockfd, int backlog);
int net_accept(int sockfd, struct sockaddr *addr, int *addrlen);
int net_recv(int fd, void *buf, uint64_t len);
int net_send(int fd, const void *buf, uint64_t len);
int net_setsockopt(int s, int level, int optname, const void *optval, uint32_t optlen);
int net_close(int fd);

#endif
