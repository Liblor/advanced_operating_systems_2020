/*
 * Copyright (c) 2020, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr 6, CH-8092 Zurich.
 */

#ifndef GIC_DIST_H_
#define GIC_DIST_H_

#include <stdint.h>
#include <aos/aos.h>

//#define GIC_DIST_DEBUG_ON
#if defined(GIC_DIST_DEBUG_ON)
#define GIC_DIST_DEBUG(x...) debug_printf("gic_dist:" x)
#else
#define GIC_DIST_DEBUG(x...) ((void)0) 
#endif


struct gic_dist_s; 


/**
 * Allocate and initizalize gic dist driver. 
 *
 * \param gds   Returns the initialized driver struct
 * \param base  The gic dist registers mapped rw and nocache
 */
errval_t gic_dist_init(struct gic_dist_s** gds, void* base);

/**
 * \brief Enable an interrupt
 *
 * \see ARM Generic Interrupt Controller Architecture Specification v1.0
 *
 * \param int_id
 * \param cpu_targets 8 Bit mask. One bit for each core in the system.
 *    (chapter 4.3.11)
 * \param prio Priority of the interrupt (lower is higher). We allow 0..15.
 *    The number of priority bits is implementation specific, but at least 16
 *    (using bits [7:4] of the priority field, chapter 3.3)
 */
errval_t gic_dist_enable_interrupt(struct gic_dist_s *gds, int int_id,
    uint8_t cpu_targets, uint16_t prio);

void gic_dist_raise_softirq(struct gic_dist_s * gds, uint8_t cpumask,
    uint8_t irq);

#endif
