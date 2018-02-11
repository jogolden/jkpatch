/* golden */
/* 2/1/2018 */

#include "uart.h"

struct mtx uart_mtx;

void init_uart() {
	mtx_init(&uart_mtx, "uart", NULL, 0);
}

int uprintf(const char *fmt, ...) {
	va_list va;

	mtx_lock_sleep(&uart_mtx, 0);

	va_start(va, fmt);
	int r = vprintf(fmt, va);
	va_end(va);

	printf("\n");

	mtx_unlock_sleep(&uart_mtx, 0);

	return r;
}
