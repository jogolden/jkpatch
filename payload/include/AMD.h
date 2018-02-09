/* golden */
/* 1/2/2018 */

// AMD x86-64 specfific static functions and definitions
// I have tailored this document for my purpose.

#ifndef _AMD_H
#define _AMD_H

// Control register bit fields

// CR0
#define CR0_PE (1 << 0) // protected mode enable
#define CR0_MP (1 << 1) // monitor co-processor
#define CR0_EM (1 << 2) // emulation
#define CR0_TS (1 << 3) // task switched
#define CR0_ET (1 << 4) // extension type
#define CR0_NE (1 << 5) // numeric error
// 6-15 reserved
#define CR0_WP (1 << 16) // write protect
// 17 reserved
#define CR0_AM (1 << 18) // alignment mask
// 19-28 reserved
#define CR0_NW (1 << 29) // not-write through
#define CR0_CD (1 << 30) // cache disable
#define CR0_PG (1 << 31) // paging
// 32-63 reserved

// CR3
#define CR3_PWT (1 << 3) // page level write through
#define CR3_PCD (1 << 4) // page level cache disable
#define CR3_PCID // PCID 0-11 bits
#define CR3_PML4 // page map level 4 physical base address

// CR4
#define	CR4_VME (1 << 0) // virtual-8086 mode extensions
#define	CR4_PVI (1 << 1) // protected mode virtual interrupts
#define	CR4_TSD (1 << 2) // time stamp enabled only in ring 0
#define	CR4_DE (1 << 3) //  debugging extensions
#define	CR4_PSE (1 << 4) // page size extension
#define	CR4_PAE (1 << 5) // physical address extension
#define	CR4_MCE (1 << 6) // machine check exception
#define	CR4_PGE (1 << 7) // page global enable
#define	CR4_PCE (1 << 8) // performance monitoring counter enable
#define	CR4_OSFXSR (1 << 9) // os support for fxsave and fxrstor instructions
#define	CR4_OSXMMEXCPT (1 << 10) // os support for unmasked simd floating point exceptions
#define	CR4_UMIP (1 << 11) // user-mode instruction prevention (SGDT, SIDT, SLDT, SMSW, and STR are disabled in user mode)
// 12 reserved
#define	CR4_VMXE (1 << 13) // virtual machine extensions enable
#define	CR4_SMXE (1 << 14) // safer mode extensions enable
// 15 reserved
#define CR4_FSGSBASE (1 << 16) // enables the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE.
#define	CR4_PCIDE (1 << 17) // PCID enable
#define	CR4_OSXSAVE	XSAVE (1 << 18) // and processor extended states enable
// 19 reserved
#define	CR4_SMEP (1 << 20) // Supervisor Mode Executions Protection Enable
#define	CR4_SMAP (1 << 21) // Supervisor Mode Access Protection Enable
// 22-63 reserved

// Register manipulation functions

static inline __attribute__((always_inline)) uint64_t __readmsr(uint32_t __register) {
	uint32_t __edx, __eax;

	__asm__ volatile (
	    "rdmsr"
	    : "=d"(__edx),
	    "=a"(__eax)
	    : "c"(__register)
	);

	return (((uint64_t)__edx) << 32) | (uint64_t)__eax;
}
static inline __attribute__((always_inline)) void __writemsr(uint32_t __register, uint64_t __msr) {
	uint32_t __low, __high;

	__low = (uint32_t)(__msr & 0xFFFFFFFF);
	__high = (uint32_t)((__msr >> 32) & 0xFFFFFFFF);

	__asm__ volatile (
	    "wrmsr"
	    : : "a"(__low),
	    "d"(__high),
	    "c"(__register)
	);
}

// CR0, CR3, and CR4 are only really relevant

static inline __attribute__((always_inline)) uint64_t __readcr0(void) {
	uint64_t cr0;

	__asm__ volatile (
	    "movq %0, %%cr0"
	    : "=r" (cr0)
	    : : "memory"
	);

	return cr0;
}
static inline __attribute__((always_inline)) void __writecr0(uint64_t cr0) {
	__asm__ volatile (
	    "movq %%cr0, %0"
	    : : "r" (cr0)
	    : "memory"
	);
}

static inline __attribute__((always_inline)) uint64_t __readcr3(void) {
	uint64_t cr3;

	__asm__ volatile (
	    "movq %0, %%cr3"
	    : "=r" (cr3)
	    : : "memory"
	);

	return cr3;
}
static inline __attribute__((always_inline)) void __writecr3(uint64_t cr3) {
	__asm__ volatile (
	    "movq %%cr3, %0"
	    : : "r" (cr3)
	    : "memory"
	);
}

static inline __attribute__((always_inline)) uint64_t __readcr4(void) {
	uint64_t cr4;

	__asm__ volatile (
	    "movq %0, %%cr4"
	    : "=r" (cr4)
	    : : "memory"
	);

	return cr4;
}
static inline __attribute__((always_inline)) void __writecr4(uint64_t cr4) {
	__asm__ volatile (
	    "movq %%cr4, %0"
	    : : "r" (cr4)
	    : "memory"
	);
}

#endif
