.intel_syntax noprefix
.text

.global _start
_start:
	call getkernbase
	mov rdi, rax
	call resolve
	xor eax, eax
	jmp payload_entry
