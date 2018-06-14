/* golden */
/* 6/11/2018 */

 // inspired by fail0verflow, of course
 // 5.05

 // ref 0xFFFFFFFF87464000

#define __Xfast_syscall							0x1C0	    
#define __copyin								0x1EA710 	
#define __copyout								0x1EA630	
#define __printf								0x436040	
#define __vprintf                               0x4360B0	
#define __malloc								0x10E250	
#define __free									0x10E460	
#define __memcpy								0x1EA530	
#define __memset								0x3205C0	
#define __memcmp								0x50AC0
#define __kmem_alloc							0xFCC80
#define __strlen                                0x3B71A0	
#define __pause									0x3FB920
#define __kthread_add							0x138360	
#define __kthread_exit							0x138640	
#define __sched_prio							0x31EE00
#define __sched_add								0x31F150
#define __kern_yield							0x3FBC40
#define __fill_regs								0x234BA0
#define __set_regs								0x234CD0
#define __create_thread							0x1BE1F0
#define __kproc_create							0x137DF0
#define __kthread_set_affinity					0x138CC0
#define __kthread_suspend_check					0x138A60
#define __kproc_kthread_add						0x138B70
#define __sx_init_flags							0xF5BB0
#define __sx_xlock								0xF5E10
#define __sx_xunlock							0xF5FD0
#define __mtx_init								0x402780
#define __mtx_lock_spin_flags					0x402100
#define __mtx_unlock_spin_flags					0x4022C0
#define __mtx_lock_sleep						0x401CD0
#define __mtx_unlock_sleep						0x401FA0
#define __fpu_kern_enter						0x1BFF90
#define __fpu_kern_leave						0x1C0090
#define __kern_reboot							0x10D390
#define __vm_map_lock_read						0x19F140	
#define __vm_map_lookup_entry					0x19F760
#define __vm_map_unlock_read					0x19F190
#define __vmspace_free							0x19EDC0
#define __vm_map_delete							0x1A19D0
#define __vm_map_protect						0x1A3A50
#define __vmspace_acquire_ref					0x19EF90	
#define __vm_map_findspace						0x1A1F60
#define __vm_map_insert							0x1A0280
#define __vm_map_lock							0x19EFF0
#define __vm_map_unlock 						0x19F060
#define __proc_rwmem							0x30D150

//net.c
#define __sys_socket							0x318EE0
#define __sys_bind								0x319820
#define __sys_listen							0x319A60
#define __sys_accept							0x31A170
#define __sys_read								0x152AB0
#define __sys_write								0x152FC0
#define __sys_setsockopt						0x31B750
#define __sys_close								0xC0EB0


#define __disable_console_output                0x19ECEB0
#define __M_TEMP					        	0x14B4110	
#define __kernel_map                            0x1AC60E0 	
#define __prison0                               0x10986a0 	
#define __rootvnode                             0x22c1a70 	
#define __allproc								0x2382FF8
