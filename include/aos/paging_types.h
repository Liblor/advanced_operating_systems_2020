/**
 * \file
 * \brief PMAP Implementaiton for AOS
 */

/*
 * Copyright (c) 2019 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef PAGING_TYPES_H_
#define PAGING_TYPES_H_ 1

#include <aos/slab.h>
#include <aos/solution.h>
#include <collections/hash_table.h>
#include <collections/range_tracker.h>
#include <collections/list.h>

#define MCN_COUNT DIVIDE_ROUND_UP(PTABLE_ENTRIES, L2_CNODE_SLOTS)

// Currently we need to avoid refilling slabs before we actually run the child
// Otherwise we get a page fault on the parent while it should be handleded
// using the child pageing state?
#define PMAP_PREALLOC_PTABLE_SLABS 8

#define PMAP_META_SIZE ROUND_UP(SLAB_STATIC_SIZE(2048, sizeof(struct ptable)), BASE_PAGE_SIZE)

#define VADDR_OFFSET ((lvaddr_t)512UL*1024*1024*1024)   // 1GB

#define PAGING_SLAB_BUFSIZE 32

#define VREGION_FLAGS_READ     0x01     // Reading allowed
#define VREGION_FLAGS_WRITE    0x02     // Writing allowed
#define VREGION_FLAGS_EXECUTE  0x04     // Execute allowed
#define VREGION_FLAGS_NOCACHE  0x08     // Caching disabled
#define VREGION_FLAGS_MPB      0x10     // Message passing buffer
#define VREGION_FLAGS_GUARD    0x20     // Guard page
#define VREGION_FLAGS_MASK     0x2f     // Mask of all individual VREGION_FLAGS

#define VREGION_FLAGS_READ_WRITE \
    (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE)
#define VREGION_FLAGS_READ_EXECUTE \
    (VREGION_FLAGS_READ | VREGION_FLAGS_EXECUTE)
#define VREGION_FLAGS_READ_WRITE_NOCACHE \
    (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE | VREGION_FLAGS_NOCACHE)
#define VREGION_FLAGS_READ_WRITE_MPB \
    (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE | VREGION_FLAGS_MPB)

#define PAGING_HASHMAP_BUCKETS 100
#define PAGING_EXCEPTION_STACK_SIZE (8 * BASE_PAGE_SIZE)

struct sanitized_range {
    const lvaddr_t base; ///< The aligned base of the range.
    const lvaddr_t end; ///< The aligned end of the range.
    const size_t size; ///< The size of the aligned ends.
};

static const inline errval_t paging_sanitize_range(
    const lvaddr_t base,
    const size_t size,
    struct sanitized_range *range
)
{
    assert(range != NULL);

    const size_t end = base + size;
    range->base = ROUND_DOWN(base, BASE_PAGE_SIZE);
    range->end = ROUND_UP(end, BASE_PAGE_SIZE);
    range->size = range->end - range->base;

    // Handle overflow.
    if (range->end < base || range->size < size) {
        return LIB_ERR_PAGING_SIZE_INVALID;
    }

    assert(range->base <= base);
    assert(range->end >= base);
    assert(range->size >= size);

    return SYS_ERR_OK;
}

static const inline errval_t paging_sanitize_size(
    const size_t size,
    const size_t *ret
)
{
    assert(ret != NULL);

    *ret = ROUND_UP(size, BASE_PAGE_SIZE);

    // Handle overflow.
    if (*ret < size) {
        return LIB_ERR_PAGING_SIZE_INVALID;
    }

    assert(*ret >= size);

    return SYS_ERR_OK;
}

struct pt_entry {
    struct capref cap;
    struct capref cap_mapping;
    struct _collections_hash_table *pt;
};

struct pt_l2_entry {
    struct capref cap;
    struct capref cap_mapping;
    struct paging_region *l3_entries[PTABLE_ENTRIES];
};

// Struct to store the paging status of a process
struct paging_state {
    struct slot_allocator *slot_alloc;
    struct slab_allocator slabs;
    struct range_tracker rt; ///< The range tracker is used to track allocated paging regions.
    struct capref cap_l0;
    struct _collections_hash_table *l0pt;
    char initial_slabs_buffer[64 * RANGE_TRACKER_NODE_SIZE]; ///< Used to initially grow the slab allocator.
    char *exception_stack_base[PAGING_EXCEPTION_STACK_SIZE];
    lvaddr_t start_addr; ///< From where on this paging state is responsible.
};

#endif // PAGING_TYPES_H_
