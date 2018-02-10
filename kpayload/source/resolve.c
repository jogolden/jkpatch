/* golden */
/* 1/2/2018 */

#include "resolve.h"

void resolve(uint64_t kernbase) {
	M_TEMP = (void *)(kernbase + __M_TEMP);
	fpu_kern_ctx = (void *)(kernbase + __fpu_kern_ctx);
	sbl_driver_mapped_pages = (const struct sbl_map_list_entry **)(kernbase + __sbl_driver_mapped_pages);
	mini_syscore_self_binary = (const uint8_t *)(kernbase + __mini_syscore_self_binary);
	sbl_keymgr_key_rbtree = (struct sbl_key_rbtree_entry **)(kernbase + __sbl_keymgr_key_rbtree);

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
	r(vmspace_free, __vmspace_free);
	r(vmspace_acquire_ref, __vmspace_acquire_ref);
	r(sceSblServiceMailbox, __sceSblServiceMailbox);
	r(sceSblAuthMgrGetSelfInfo, __sceSblAuthMgrGetSelfInfo);
	r(sceSblAuthMgrSmStart, __sceSblAuthMgrSmStart);
	r(sceSblAuthMgrIsLoadable2, __sceSblAuthMgrIsLoadable2);
	r(sceSblAuthMgrVerifyHeader, __sceSblAuthMgrVerifyHeader);
	r(sceSblKeymgrSmCallfunc, __sceSblKeymgrSmCallfunc);
	r(sceSblPfsKeymgrGenEKpfsForGDGPAC, __sceSblPfsKeymgrGenEKpfsForGDGPAC);
	r(sceSblPfsSetKey, __sceSblPfsSetKey);
	r(sceSblPfsClearKey, __sceSblPfsClearKey);
	r(sceSblServiceCrypt, __sceSblServiceCrypt);
	r(sceSblServiceCryptAsync, __sceSblServiceCryptAsync);
	r(AesCbcCfb128Encrypt, __AesCbcCfb128Encrypt);
	r(AesCbcCfb128Decrypt, __AesCbcCfb128Decrypt);
	r(Sha256Hash, __Sha256Hash);
	r(Sha256Hmac, __Sha256Hmac);
	r(RsaesPkcs1v15Enc2048, __RsaesPkcs1v15Enc2048);
	r(RsaesPkcs1v15Dec2048CRT, __RsaesPkcs1v15Dec2048CRT);
}
