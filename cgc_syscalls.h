
#ifndef __CGC_SYSCALLS
#define __CGC_SYSCALLS

#define CGC_SYS_TERMINATE 1
#define CGC_SYS_TRANSMIT 2
#define CGC_SYS_RECEIVE 3
#define CGC_SYS_FDWAIT 4
#define CGC_SYS_ALLOCATE 5
#define CGC_SYS_DEALLOCATE 6
#define CGC_SYS_RANDOM 7


//error numbers
#define CGC_EBADF  1
#define CGC_EFAULT 2
#define CGC_EINVAL 3
#define CGC_ENOMEM 4
#define CGC_ENOSYS 5
#define CGC_EPIPE  6

#define GDT_ENTRY_TLS_MIN 6
#define GDT_ENTRY_TLS_MAX 8

#define	CGC_FD_SETSIZE	1024

typedef long int cgc_fd_mask;

#define	CGC_NFDBITS (8 * sizeof(cgc_fd_mask))

struct cgc_fd_set {
	cgc_fd_mask _fd_bits[CGC_FD_SETSIZE / CGC_NFDBITS];
};

#define	CGC_FD_ZERO(set)							\
	do {								\
		int __i;						\
		for (__i = 0; __i < (CGC_FD_SETSIZE / CGC_NFDBITS); __i++)	\
			(set)->_fd_bits[__i] = 0;				\
	} while (0)
#define	CGC_FD_SET(b, set) \
	((set)->_fd_bits[b / CGC_NFDBITS] |= (1 << (b & (CGC_NFDBITS - 1))))
#define	CGC_FD_CLR(b, set) \
	((set)->_fd_bits[b / CGC_NFDBITS] &= ~(1 << (b & (CGC_NFDBITS - 1))))
#define	CGC_FD_ISSET(b, set) \
	((set)->_fd_bits[b / CGC_NFDBITS] & (1 << (b & (CGC_NFDBITS - 1))))

struct cgc_timeval {
	int tv_sec;
	int tv_usec;
};

#endif
