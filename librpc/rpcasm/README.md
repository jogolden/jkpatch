#  rpcasm

```c
void *rpcldr(void) {
	scePThreadCreate(&thread, 0LL, rpcstub + *(_QWORD *)(rpcstub + 8), 0LL, 0LL);
	return (void *)rpcstub;
}
```

```c
void __noreturn rpcstub() {
	while (1) {
		if (rpc_go) {
			rpc_rax = rpc_rip(rpc_rdi, rpc_rsi, rpc_rdx, rpc_rcx, rpc_r8, rpc_r9);
			rpc_go = 0;
			rpc_done = 1;
		}
		
		sceKernelUsleep(0x8000);
	}
}
```

These two files are compiled with [NASM](http://www.nasm.us/) and I have put the byte code in rpcasm.h! This is the core of the function calling RPC commands. Have fun!
