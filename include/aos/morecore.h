/**
 * \file
 * \brief
 */

/*
 * Copyright (c) 2007, 2008, 2009, ETH Zurich.
 * Copyright (c) 2014, HP Labs.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef BARRELFISH_MORECORE_H
#define BARRELFISH_MORECORE_H

#include <sys/cdefs.h>

__BEGIN_DECLS
// 1TB
#define MORECORE_VADDR_ZONE_SIZE (1024UL*1024*1024*1024)
errval_t morecore_init(size_t alignment);
void morecore_use_optimal(void);
errval_t morecore_reinit(void);

__END_DECLS

#endif
