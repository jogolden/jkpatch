/* golden */
/* 1/2/2018 */

#include "resolve.h"

void resolve(uint64_t kernbase) {
	M_TEMP = (void *)(kernbase + __M_TEMP);

#define r(name, offset) name = (void *)(kernbase + offset)
	r(printf, __printf);
	r(k_malloc, __malloc);
	r(k_free, __free);
	r(k_memcpy, __memcpy);
	r(k_memset, __memset);
	r(k_memcmp, __memcmp);
	r(k_strlen, __strlen);
	r(kthread_add, __kthread_add);
	r(proc_rwmem, __proc_rwmem);
	r(sx_init_flags, __sx_init_flags);
	r(sx_xlock, __sx_xlock);
	r(sx_xunlock, __sx_xunlock);
	r(fpu_kern_enter, __fpu_kern_enter);
	r(fpu_kern_leave, __fpu_kern_leave);
	r(vm_map_lock_read, __vm_map_lock_read);
	r(vm_map_lookup_entry, __vm_map_lookup_entry);
	r(vm_map_unlock_read, __vm_map_unlock_read);
	r(vmspace_free, __vmspace_free);
	r(vmspace_acquire_ref, __vmspace_acquire_ref);
}
