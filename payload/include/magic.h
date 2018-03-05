/* golden */
/* 1/2/2018 */

// inspired by fail0verflow, of course
// 4.55

// ref FFFFFFFF8F59C000

#define __Xfast_syscall							0x3095D0
#define __copyin								0x14A890
#define __copyout								0x14A7B0
#define __printf								0x017F30
#define __malloc								0x3F7750
#define __free									0x3F7930
#define __memcpy								0x14A6B0
#define __memset								0x302BD0
#define __memcmp								0x242A60
#define __kmem_alloc							0x16ECD0
#define __strlen                                0x3514F0

#define __disable_console_output                0x1997BC8
#define __M_TEMP					        	0x1993B30
#define __kernel_map                            0x1B31218
#define __prison0                               0x10399B0
#define __rootvnode                             0x21AFA30
