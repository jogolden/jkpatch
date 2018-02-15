; rpcldr.s
; golden

BITS 64
DEFAULT REL

magic: db 'RLDR'
entry: dq rpcldr
ldr_done: db 0
stubentry: dq 0

str_libkernel: db 'libkernel.sprx', 0
str_libkernelweb: db 'libkernel_web.sprx', 0
str_libkernelsys: db 'libkernel_sys.sprx', 0
libkernel: dq 0

str_scePthreadCreate: db 'scePthreadCreate', 0
scePthreadCreate: dq 0

hthread: dq 0
str_rpcstub: db 'rpcstub', 0

; rpcldr()
rpcldr:
	; get libkernel handle
	mov rcx, 0
	lea rdx, [libkernel]
	mov rsi, 0
	lea rdi, [str_libkernel]
	call sys_dynlib_load_prx
	test rax, rax
	je resolve

	mov rcx, 0
	lea rdx, [libkernel]
	mov rsi, 0
	lea rdi, [str_libkernelweb]
	call sys_dynlib_load_prx
	test rax, rax
	je resolve

	mov rcx, 0
	lea rdx, [libkernel]
	mov rsi, 0
	lea rdi, [str_libkernelsys]
	call sys_dynlib_load_prx

resolve:
	; resolve scePthreadCreate
	lea rdx, [scePthreadCreate]
	lea rsi, [str_scePthreadCreate]
	mov rdi, qword [libkernel]
	call sys_dynlib_dlsym

	lea r8, [str_rpcstub]
	mov rcx, 0
	mov rdx, qword [stubentry]
	mov rsi, 0
	lea rdi, [hthread]
	mov r12, qword [scePthreadCreate]
	call r12

	mov rdi, 0
	call sys_thr_exit
	retn

sys_dynlib_load_prx:
	mov rax, 594
	mov r10, rcx
	syscall
	retn

sys_dynlib_dlsym:
	mov rax, 591
	mov r10, rcx
	syscall
	retn

sys_thr_exit:
	mov rax, 431
	mov r10, rcx
	syscall
	retn
