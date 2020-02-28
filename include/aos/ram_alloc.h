/**
 * \file
 * \brief RAM allocator code (client-side) definitions
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2011, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */


#ifndef BARRELFISH_RAM_ALLOC_H
#define BARRELFISH_RAM_ALLOC_H

#include <stdint.h>
#include <errors/errno.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

struct capref;

typedef errval_t (* ram_alloc_func_t)(struct capref *ret, size_t size, size_t alignment);

errval_t ram_alloc_fixed(struct capref *ret, size_t size, size_t alignment);
errval_t ram_alloc_aligned(struct capref *ret, size_t size, size_t alignment);
errval_t ram_alloc(struct capref *retcap, size_t size);
errval_t ram_available(genpaddr_t *available, genpaddr_t *total);
errval_t ram_alloc_set(ram_alloc_func_t local_allocator);
void ram_set_affinity(uint64_t minbase, uint64_t maxlimit);
void ram_get_affinity(uint64_t *minbase, uint64_t *maxlimit);
void ram_alloc_init(void);

__END_DECLS

#endif // BARRELFISH_RAM_ALLOC_H
