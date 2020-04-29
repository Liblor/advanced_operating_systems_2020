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

#include <barrelfish_kpi/paging_arch.h>
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

#define PAGING_CHECK_RANGE(base, size) \
    if (size == 0) { \
        return LIB_ERR_PAGING_SIZE_INVALID; \
    } \
    if (size % BASE_PAGE_SIZE != 0) { \
        return LIB_ERR_PAGING_SIZE_INVALID; \
    } \
    if (base % BASE_PAGE_SIZE != 0) { \
        return LIB_ERR_PAGING_VADDR_NOT_ALIGNED; \
    } \
    if (base + size < base) { \
        return LIB_ERR_PAGING_SIZE_INVALID; \
    }

#define PAGING_CHECK_SIZE(size) \
    if (size == 0) { \
        return LIB_ERR_PAGING_SIZE_INVALID; \
    } \

#define PAGING_SLAB_THRESHOLD (48)
#define PAGING_LOCK thread_mutex_lock_nested(&st->mutex)

struct frame_mapping_pair {
    struct capref frame; ///< The frame capability used to back the memory of the mapping.
    struct capref mapping; ///< The mapping capability.
    struct page_table *pt; ///< The page table in which the frame is mapped.
};

typedef int paging_flags_t;

struct paging_region {
    struct thread_mutex *mutex;
    paging_flags_t flags; ///< The flags with which new frames will be mapped.
    struct range_tracker rt; ///< For managing the second layer, i.e., the actual mappings.
    struct rtnode *node; ///< The node in the upper layer range tracker representing this paging region.
    bool implicit; // Whether this paging region was created automatically or via the paging_region API.
};

struct page_table;
struct page_table_entries {
    struct page_table *e[PTABLE_ENTRIES/2];
};

struct page_table {
    enum objtype type;
    struct capref cap;
    struct capref cap_mapping; ///< The mapping capability that was created when this page_table was mapped. Is NULL_CAP if the page_table represents the L0 pagetable.
    struct page_table_entries *entries[2];
};

// Struct to store the paging status of a process
struct paging_state {
    struct thread_mutex mutex;
    struct slot_allocator *slot_alloc;
    struct slab_allocator slabs;
    struct slab_allocator slabs_pr;
    struct slab_allocator slabs_fmp;
    struct slab_allocator slabs_pt;
    struct slab_allocator slabs_pte;
    struct range_tracker rt; ///< The range tracker is used to track allocated paging regions.
    struct page_table l0pt;
    struct page_table_entries l0pte0;
    struct page_table_entries l0pte1;
    char initial_slabs_buffer[64 * RANGE_TRACKER_NODE_SIZE]; ///< Used to initially grow the slab allocator.
    char initial_slabs_pr_buffer[2 * PAGING_SLAB_THRESHOLD * sizeof(struct paging_region)]; ///< Used to initially grow the slab_pr allocator.
    char initial_slabs_fmp_buffer[2 * PAGING_SLAB_THRESHOLD * sizeof(struct frame_mapping_pair)]; ///< Used to initially grow the slab_fmp allocator.
    char initial_slabs_pt_buffer[2 * PAGING_SLAB_THRESHOLD * sizeof(struct page_table)]; ///< Used to initially grow the slab_pt allocator.
    char initial_slabs_pte_buffer[2 * PAGING_SLAB_THRESHOLD * sizeof(struct page_table_entries)]; ///< Used to initially grow the slab_pte allocator.
    char *exception_stack_base[PAGING_EXCEPTION_STACK_SIZE];
    lvaddr_t start_addr; ///< From where on this paging state is responsible.
};

#endif // PAGING_TYPES_H_
