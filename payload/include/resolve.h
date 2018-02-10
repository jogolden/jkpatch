/* golden */
/* 1/2/2018 */

#ifndef _RESOLVE_H
#define _RESOLVE_H

#include "jkpatch.h"

// data
void *M_TEMP;

/** functions **/
// freebsd/common
int (*printf)(const char *fmt, ...);
void *(*k_malloc)(unsigned long size, void *type, int flags);
void (*k_free)(void *addr, void *type);
void (*k_memcpy)(void *dst, const void *src, size_t len);
void *(*k_memset)(void * ptr, int value, size_t num);
int (*k_memcmp)(const void * ptr1, const void * ptr2, size_t num);
size_t (*k_strlen)(const char *str);
int (*kthread_add)(void (*func)(void *), void *arg, struct proc *procp, struct thread **newtdpp, int flags, int pages, const char *fmt, ...);
int (*proc_rwmem)(struct proc *p, struct uio *uio);
void (*sx_init_flags)(struct sx *sx, const char *description, int opts);
void (*sx_xlock)(struct sx *sx);
void (*sx_xunlock)(struct sx *sx);
int (*fpu_kern_enter)(struct thread *td, void *ctx, unsigned int flags);
int (*fpu_kern_leave)(struct thread *td, void *ctx);

void resolve(uint64_t kernbase);

#endif
