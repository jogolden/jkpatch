; rpcstub.s
; golden

BITS 64
DEFAULT REL

magic: db 'RSTB'
entry: dq rpcstub

; libkernel: int (*sceKernelUsleep)(unsigned int microseconds);
sceKernelUsleep: dq 0

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

rpcstub:
	cmp byte [rpc_go], 0
	jz rpc_end

	; call
	mov r9, qword [rpc_r9]
	mov r8, qword [rpc_r8]
	mov rcx, qword [rpc_rcx]
	mov rdx, qword [rpc_rdx]
	mov rsi, qword [rpc_rsi]
	mov rdi, qword [rpc_rdi]
	call qword [rpc_rip]

	mov qword [rpc_rax], rax

	; reset variables
	mov byte [rpc_go], 0
	mov byte [rpc_done], 1

rpc_end:
	; sleep a little
	mov rdi, 0x8000
	call qword [sceKernelUsleep]

	jmp rpcstub
	xor eax, eax
	ret

