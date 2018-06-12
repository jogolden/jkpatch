/* golden */
/* 1/2/2018 */

#include "resolve.h"

void resolve(uint64_t kernbase) {
	M_TEMP = (void *)(kernbase + __M_TEMP);

#define r(name, offset) name = (void *)(kernbase + offset)
	r(printf, __printf);
	r(vprintf, __vprintf);
	r(malloc, __malloc);
	r(free, __free);
	r(memcpy, __memcpy);
	r(memset, __memset);
	r(memcmp, __memcmp);
	r(strlen, __strlen);
	r(pause, __pause);
	r(kthread_add, __kthread_add);
	r(kthread_exit, __kthread_exit);
	r(sched_prio, __sched_prio);
	r(sched_add, __sched_add);
	r(kern_yield, __kern_yield);
	r(create_thread, __create_thread);
	r(kthread_suspend_check, __kthread_suspend_check);
	r(kthread_set_affinity, __kthread_set_affinity);
	r(kproc_create, __kproc_create);
	r(kproc_kthread_add, __kproc_kthread_add);
	r(proc_rwmem, __proc_rwmem);
	r(sx_init_flags, __sx_init_flags);
	r(sx_xlock, __sx_xlock);
	r(sx_xunlock, __sx_xunlock);
	r(mtx_init, __mtx_init);
	r(mtx_lock_spin_flags, __mtx_lock_spin_flags);
	r(mtx_unlock_spin_flags, __mtx_unlock_spin_flags);
	r(mtx_lock_sleep, __mtx_lock_sleep);
	r(mtx_unlock_sleep, __mtx_unlock_sleep);
	r(fpu_kern_enter, __fpu_kern_enter);
	r(fpu_kern_leave, __fpu_kern_leave);
	r(kern_reboot, __kern_reboot);
	r(vm_map_lock_read, __vm_map_lock_read);
	r(vm_map_lookup_entry, __vm_map_lookup_entry);
	r(vm_map_unlock_read, __vm_map_unlock_read);
	r(vm_map_findspace, __vm_map_findspace);
	r(vm_map_insert, __vm_map_insert);
	r(vm_map_lock, __vm_map_lock);
	r(vm_map_unlock, __vm_map_unlock);
	r(vm_map_delete, __vm_map_delete);
	r(vm_map_protect, __vm_map_protect);
	r(vmspace_free, __vmspace_free);
	r(vmspace_acquire_ref, __vmspace_acquire_ref);
	r(fill_regs, __fill_regs);
	r(set_regs, __set_regs);
}
