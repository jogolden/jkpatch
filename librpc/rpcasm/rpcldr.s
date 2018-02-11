; rpcldr.s
; golden

BITS 64
DEFAULT REL

magic db 'RLDR'
entry dq rpcldr

; libkernel: int (*scePthreadCreate)(ScePthread *thread, const ScePthreadAttr *attr, void *(*entry)(void *), void *arg, const char *name);
scePthreadCreate dq 0

; pointer to rpcstub
rpcstub: dq 0
thread: dq 0

; void *rpcldr(void);
rpcldr:
	push rbp
	mov rbp, rsp
	push r15

	; resolve entry
	mov r15, qword [rpcstub]
	mov rdx, qword [r15 + 8]
	add rdx, r15

	; start thread
	mov r8, 0
	mov rcx, 0
	mov rsi, 0
	lea rdi, [thread]
	call qword [scePthreadCreate]

	mov rax, r15
	pop r15
	pop rbp
	retn
