/* golden */
/* 2/1/2018 */

#ifndef _UART_H
#define _UART_H

#include "jkpayload.h"

extern struct mtx uart_mtx;

void init_uart();
int uprintf(const char *fmt, ...);

#endif
