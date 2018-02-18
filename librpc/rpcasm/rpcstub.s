; rpcstub.s
; golden

BITS 64
DEFAULT REL

magic: db 'RSTB'
entry: dq rpcstub

; registers
rpc_rip: dq 0
rpc_rdi: dq 0
rpc_rsi: dq 0
rpc_rdx: dq 0
rpc_rcx: dq 0
rpc_r8: dq 0
rpc_r9: dq 0
rpc_rax: dq 0

; variables
rpc_go: db 0
rpc_done: db 0

str_libkernel: db 'libkernel.sprx', 0
str_libkernelweb: db 'libkernel_web.sprx', 0
str_libkernelsys: db 'libkernel_sys.sprx', 0

libkernel: dq 0
str_sceKernelSleep: db 'sceKernelUsleep', 0
sceKernelUsleep: dq 0

rpcstub:
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
	; resolve sceKernelUsleep
	lea rdx, [sceKernelUsleep]
	lea rsi, [str_sceKernelSleep]
	mov rdi, qword [libkernel]
	call sys_dynlib_dlsym

loop:
	cmp byte [rpc_go], 0
	jz end

	; call
	mov r9, qword [rpc_r9]
	mov r8, qword [rpc_r8]
	mov rcx, qword [rpc_rcx]
	mov rdx, qword [rpc_rdx]
	mov rsi, qword [rpc_rsi]
	mov rdi, qword [rpc_rdi]
	mov r12, qword [rpc_rip]
	call r12

	mov qword [rpc_rax], rax

	; reset variables
	mov byte [rpc_go], 0
	mov byte [rpc_done], 1

end:
	; sleep for 100000 microseconds
	mov rdi, 100000
	mov r12, qword [sceKernelUsleep]
	call r12

	jmp loop

	xor eax, eax
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
