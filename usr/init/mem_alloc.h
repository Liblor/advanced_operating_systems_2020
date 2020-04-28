/**
 * \file
 * \brief ram allocator functions
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _INIT_MEM_ALLOC_H_
#define _INIT_MEM_ALLOC_H_

#include <stdio.h>
#include <aos/aos.h>

extern struct bootinfo *bi;
extern struct mm aos_mm;

errval_t initialize_ram_alloc(size_t num_cores);
errval_t ram_alloc_aligned_handler(const size_t bytes, const size_t alignment, struct capref *retcap, size_t *retbytes);
errval_t aos_ram_alloc_aligned(struct capref *ret, size_t size, size_t alignment);
errval_t aos_ram_free(struct capref cap, size_t bytes);

#endif /* _INIT_MEM_ALLOC_H_ */
