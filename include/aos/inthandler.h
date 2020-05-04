/*
 * Copyright (c) 2011, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _AOS_INTHANDLER_H
#define _AOS_INTHANDLER_H

#include <sys/cdefs.h>
#include <aos/caddr.h>
#include <aos/waitset.h>
#include <errors/errno.h>

__BEGIN_DECLS


/**
 * Connect a destination cap to a handler. Interrupt messages will 
 * be dispatched on the passed waitset
 *  
 * \param dst_cap The destination cap to use
 * \param handler The handler to be called on interrupt
 */
errval_t inthandler_setup(struct capref dst_cap, struct waitset *ws,
                          struct event_closure handler);

/**
 * Allocate a new IRQ destination capability for the current core.
 * This function assumes that a IRQ table cap is located in in cap_irq, the
 * init process will get this capability from the cpu driver.
 *
 * \param vec_hint If only a specific
 * \param retcap The returned IRQDstCap capability
 */
errval_t inthandler_alloc_dest_irq_cap(int vec_hint, struct capref *retcap);

__END_DECLS

#endif
