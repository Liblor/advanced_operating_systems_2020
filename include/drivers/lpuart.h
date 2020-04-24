/*
 * Copyright (c) 2020, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr 6, CH-8092 Zurich.
 */

#ifndef LPUART_H_
#define LPUART_H_

#include <stdint.h>
#include <aos/aos.h>

//#define LPUART_DEBUG_ON
#if defined(LPUART_DEBUG_ON)
#define LPUART_DEBUG(x...) debug_printf("lpuart:" x)
#else
#define LPUART_DEBUG(x...) ((void)0) 
#endif 

#define IMX8X_UART0_INT 257
#define IMX8X_UART1_INT 258
#define IMX8X_UART2_INT 259
#define IMX8X_UART3_INT 260 

struct lpuart_s;

/*
 * Initialize driver using the virtual base address base.
 * Make sure base is mapped read/write without caching.
 * Fails on sanity checks.
 *
 * \param s     Allocates and returns a driver instance
 * \param base  Location of the registers
 */
errval_t lpuart_init(struct lpuart_s** s, void *base);

/*
 * Enable the receive interrupt 
 */
errval_t lpuart_enable_interrupt(struct lpuart_s * s);

/*
 * putchar. Blocks until device is ready to print char
 */
errval_t lpuart_putchar(struct lpuart_s* s, char c);

/*
 * getchar. Non blocking. If no data is available
 * returns LPUART_ERR_NO_DATA. If the device has lost data
 * due to a input buffer overrun, it will return
 * LPUAR_ERR_RCV_OVERRUN.
 */
errval_t lpuart_getchar(struct lpuart_s* s, char *c);


#endif
