/**
 * \file
 * \brief AOS paging helpers.
 */

/*
 * Copyright (c) 2012, 2013, 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <aos/aos.h>
#include <aos/paging.h>
#include <aos/vaddr_regions.h>
#include <aos/except.h>
#include <aos/slab.h>
#include "threads_priv.h"

#include <stdio.h>
#include <string.h>

static struct paging_state current;



/**
 * \brief Helper function that allocates a slot and
 *        creates a aarch64 page table capability for a certain level
 */
static errval_t pt_alloc(struct paging_state * st, enum objtype type,
                         struct capref *ret)
{
    DEBUG_BEGIN;
    errval_t err;
    err = st->slot_alloc->alloc(st->slot_alloc, ret);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc failed: %s\n", err_getstring(err));
        return err;
    }
    err = vnode_create(*ret, type);
    if (err_is_fail(err)) {
        debug_printf("vnode_create failed: %s\n", err_getstring(err));
        return err;
    }
    return SYS_ERR_OK;
}

__attribute__((unused)) static errval_t pt_alloc_l1(struct paging_state * st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l1, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l2(struct paging_state * st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l2, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l3(struct paging_state * st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l3, ret);
}


/**
 * TODO(M2): Implement this function.
 * TODO(M4): Improve this function.
 * \brief Initialize the paging_state struct for the paging
 *        state of the calling process.
 *
 * \param st The struct to be initialized, must not be NULL.
 * \param start_vaddr Virtual address allocation should start at
 *        this address.
 * \param cap_l0 Reference to the cap of the L0 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state(struct paging_state *st, lvaddr_t start_vaddr,
                           struct capref cap_l0, struct slot_allocator *ca)
{
    DEBUG_BEGIN;
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    st->slot_alloc = ca;
    st->cap_l0 = cap_l0;
    slab_init(&st->slabs, sizeof(struct vaddr_region), slab_default_refill);
    slab_grow(&st->slabs, st->buf, sizeof(st->buf));

    add_region(st, start_vaddr, 0xffffffffffff-start_vaddr, NULL);
    return SYS_ERR_OK;
}

__attribute__((__unused__)) static
void* paging_slab_alloc(size_t size) {
    return malloc(size);
}

__attribute__((__unused__))
static
void paging_slab_free(void* ptr) {
    free(ptr);
}

__attribute__((__unused__))
static inline
void create_hashtable(collections_hash_table **hashmap) {
    collections_hash_create_with_buckets_and_memory_functions(hashmap, PAGING_HASHMAP_BUCKETS, NULL,
            paging_slab_alloc, paging_slab_free);
}

/**
 * TODO(M2): Implement this function.
 * TODO(M4): Improve this function.
 * \brief Initialize the paging_state struct for the paging state
 *        of a child process.
 *
 * \param st The struct to be initialized, must not be NULL.
 * \param start_vaddr Virtual address allocation should start at
 *        this address.
 * \param cap_l0 Reference to the cap of the L1 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state_foreign(struct paging_state *st, lvaddr_t start_vaddr,
                                   struct capref cap_l0, struct slot_allocator *ca)
{
    DEBUG_BEGIN;
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    paging_init_state(st, VADDR_OFFSET, cap_l0, get_default_slot_allocator());
    return SYS_ERR_OK;
}

/**
 * \brief This function initializes the paging for this domain
 * It is called once before main.
 */
errval_t paging_init(void)
{
    DEBUG_BEGIN;
    // TODO (M4): initialize self-paging handler
    // TIP: use thread_set_exception_handler() to setup a page fault handler
    // TIP: Think about the fact that later on, you'll have to make sure that
    // you can handle page faults in any thread of a domain.
    // TIP: it might be a good idea to call paging_init_state() from here to
    // avoid code duplication.

    // TODO check parameters
    struct capref pdir = (struct capref) {
            .cnode = cnode_page,
            .slot = 0,
    };
    paging_init_state(&current, VADDR_OFFSET, pdir, get_default_slot_allocator());
    set_current_paging_state(&current);
    return SYS_ERR_OK;
}


/**
 * \brief Initialize per-thread paging state
 */
void paging_init_onthread(struct thread *t)
{
    DEBUG_BEGIN;
    // TODO (M4): setup exception handler for thread `t'.
}

/**
 * \brief Initialize a paging region in `pr`, such that it  starts
 * from base and contains size bytes.
 */
errval_t paging_region_init_fixed(struct paging_state *st, struct paging_region *pr,
                                  lvaddr_t base, size_t size, paging_flags_t flags)
{
    DEBUG_BEGIN;
    pr->base_addr = (lvaddr_t)base;
    pr->current_addr = pr->base_addr;
    pr->region_size = size;
    pr->flags = flags;

    //Add the region to a datastructure and ensure paging_alloc
    //will return non-overlapping regions.
    struct vaddr_region *ret;
    errval_t err = alloc_vaddr_region(st, pr->base_addr, size, &ret);
    if (err_is_fail(err)) {
        return err;
    }
    ret->region = pr;
    return SYS_ERR_OK;
}

/**
 * \brief Initialize a paging region in `pr`, such that it contains at least
 * size bytes and is aligned to a multiple of alignment.
 */
errval_t paging_region_init_aligned(struct paging_state *st, struct paging_region *pr,
                                    size_t size, size_t alignment, paging_flags_t flags)
{
    DEBUG_BEGIN;
    void *base;
    errval_t err = paging_alloc(st, &base, size, alignment);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_region_init: paging_alloc failed\n");
        return err_push(err, LIB_ERR_VSPACE_MMU_AWARE_INIT);
    }

    return paging_region_init_fixed(st, pr, (lvaddr_t)base, size, flags);
}

/**
 * \brief Initialize a paging region in `pr`, such that it contains at least
 * size bytes.
 *
 * This function gets used in some of the code that is responsible
 * for allocating Frame (and other) capabilities.
 */
errval_t paging_region_init(struct paging_state *st, struct paging_region *pr,
                            size_t size, paging_flags_t flags)
{
    return paging_region_init_aligned(st, pr, size, BASE_PAGE_SIZE, flags);
}

/**
 * \brief return a pointer to a bit of the paging region `pr`.
 * This function gets used in some of the code that is responsible
 * for allocating Frame (and other) capabilities.
 */
errval_t paging_region_map(struct paging_region *pr, size_t req_size, void **retbuf,
                           size_t *ret_size)
{
    DEBUG_BEGIN;
    lvaddr_t end_addr = pr->base_addr + pr->region_size;
    ssize_t rem = end_addr - pr->current_addr;
    if (rem > req_size) {
        // ok
        *retbuf = (void *)pr->current_addr;
        *ret_size = req_size;
        pr->current_addr += req_size;
    } else if (rem > 0) {
        *retbuf = (void *)pr->current_addr;
        *ret_size = rem;
        pr->current_addr += rem;
        debug_printf("exhausted paging region, "
                     "expect badness on next allocation\n");
    } else {
        return LIB_ERR_VSPACE_MMU_AWARE_NO_SPACE;
    }
    return SYS_ERR_OK;
}

/**
 * TODO(M2): As an OPTIONAL part of M2 implement this function
 * \brief free a bit of the paging region `pr`.
 * This function gets used in some of the code that is responsible
 * for allocating Frame (and other) capabilities.
 * NOTE: Implementing this function is optional.
 */
errval_t paging_region_unmap(struct paging_region *pr, lvaddr_t base, size_t bytes)
{
    // XXX: should free up some space in paging region, however need to track
    //      holes for non-trivial case
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * TODO(M2): Implement this function.
 * \brief Find a bit of free virtual address space that is large enough to accomodate a
 *        buffer of size 'bytes'.
 *
 * \param st A pointer to the paging state.
 * \param buf This parameter is used to return the free virtual address that was found.
 * \param bytes The number of bytes that need to be free (at the minimum) at the found
 *        virtual address.
 * \param alignment The address needs to be a multiple of 'alignment'.
 * \return Either SYS_ERR_OK if no error occured or an error
 *        indicating what went wrong otherwise.
 */
errval_t paging_alloc(struct paging_state *st, void **buf, size_t bytes, size_t alignment)
{
    DEBUG_BEGIN;
    /**
     * TODO(M2): Implement this function
     * \brief Find a bit of free virtual address space that is large enough to
     *        accomodate a buffer of size `bytes`.
     */

    *buf = NULL;
    slab_ensure_threshold(&st->slabs, 12);
    errval_t err = find_region(st, buf, bytes, alignment);
    if (err_is_fail(err)) { return err; }

    return SYS_ERR_OK;
}

/**
 * TODO(M2): Implement this function.
 * \brief Finds a free virtual address and maps a frame at that address
 *
 * \param st A pointer to the paging state.
 * \param buf This will parameter will be used to return the free virtual
 * address at which a new frame as been mapped.
 * \param bytes The number of bytes that need to be free (at the minimum)
 *        at the virtual address found.
 * \param frame A reference to the frame cap that is supposed to be mapped.
 * \param flags The flags that are to be set for the newly mapped region,
 *        see 'paging_flags_t' in paging_types.h .
 * \param arg1 Currently unused argument.
 * \param arg2 Currently unused argument.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_map_frame_attr(struct paging_state *st, void **buf, size_t bytes,
                               struct capref frame, int flags, void *arg1, void *arg2)
{
    DEBUG_BEGIN;

    // TODO(M2): Implement me (done, remove todo after review)
    // - Call paging_alloc to get a free virtual address region of the requested size
    // - Map the user provided frame at the free virtual address

    errval_t err = paging_alloc(st, buf, bytes, BASE_PAGE_SIZE);
    if (err_is_fail(err)) { return err; }

    return paging_map_fixed_attr(st, (lvaddr_t)(*buf), frame, bytes, flags);

}

errval_t slab_refill_no_pagefault(struct slab_allocator *slabs, struct capref frame,
                                  size_t minbytes)
{
    DEBUG_BEGIN;
    // Refill the two-level slot allocator without causing a page-fault
    return SYS_ERR_OK;
}

static inline errval_t paging_create_vnode(struct paging_state *st, enum objtype type, struct capref *parent,
        struct capref *ret, const uint16_t index, struct capref *mapping)
{
    DEBUG_BEGIN;
    errval_t err;
    const int flags = VREGION_FLAGS_READ_WRITE;

    err = pt_alloc(st, type, ret);
    if (err_is_fail(err)) {
        debug_printf("pt_alloc failed: %s\n", err_getstring(err));
        err_push(err, LIB_ERR_VNODE_CREATE);
        goto error_cleanup;
    }
    err = st->slot_alloc->alloc(st->slot_alloc, mapping);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc failed: %s\n", err_getstring(err));
        goto error_cleanup;
    }
    err = vnode_map(*parent, *ret, index, flags, 0, 1, *mapping);
    if (err_is_fail(err)) {
        debug_printf("vnode_map failed: %s\n", err_getstring(err));
        err_push(err, LIB_ERR_VNODE_MAP);
        goto error_cleanup;
    }
    return SYS_ERR_OK;

    error_cleanup:
    st->slot_alloc->free(st->slot_alloc, *ret);
    st->slot_alloc->free(st->slot_alloc, *mapping);
    return err;
}

__attribute__((__unused__))
static inline void
ensure_correct_pagetable_mapping(struct paging_state *st, lvaddr_t vaddr) {
    const uint16_t _l0_idx = VMSAv8_64_L0_INDEX(vaddr);
    const uint16_t _l1_idx = VMSAv8_64_L1_INDEX(vaddr);
    const uint16_t _l2_idx = VMSAv8_64_L2_INDEX(vaddr);
    const uint16_t _l3_idx = VMSAv8_64_L3_INDEX(vaddr);
    // asserts
    assert(!capref_is_null(st->cap_l0));
    struct pt_entry *pt_l1 = collections_hash_find(st->l0pt, _l0_idx);
    assert(pt_l1!= NULL);
    assert(!capref_is_null(pt_l1->cap_mapping));
    assert(!capref_is_null(pt_l1->cap));

    struct pt_entry *pt_l2 = collections_hash_find(pt_l1->pt, _l1_idx);
    assert(pt_l2!= NULL);
    assert(!capref_is_null(pt_l2->cap_mapping));
    assert(!capref_is_null(pt_l2->cap));

    struct pt_l2_entry *pt_l3 = collections_hash_find(pt_l2->pt, _l2_idx);
    assert(pt_l3!= NULL);
    assert(!capref_is_null(pt_l3->cap_mapping));
    assert(!capref_is_null(pt_l3->cap));

    struct paging_region *l3_entry = pt_l3->l3_entries[_l3_idx];
    assert(l3_entry != NULL);
    assert(!capref_is_null(l3_entry->frame_cap));
    assert(!capref_is_null(l3_entry->cap_mapping));
}

// create paging directory
static inline errval_t paging_create_pd(struct paging_state *st, const lvaddr_t vaddr, struct pt_l2_entry **ret_l2entry)
{
    errval_t err;

    if (st->l0pt == NULL) {
        create_hashtable(&st->l0pt);
        if (st->l0pt == NULL ) {
            return LIB_ERR_MALLOC_FAIL;
        }
    }

    // TODO: refactor
    // mapping l0 -> l1
    const uint16_t l0_idx = VMSAv8_64_L0_INDEX(vaddr);
    struct pt_entry *l0entry = collections_hash_find(st->l0pt, l0_idx);
    if (l0entry == NULL) {
        l0entry = paging_slab_alloc(sizeof(struct pt_entry));
        if (l0entry == NULL) {
            // TODO: do we recover from alloc errors with free of resources?
            return LIB_ERR_MALLOC_FAIL;
        }
        collections_hash_table **l1pt = &l0entry->pt;
        create_hashtable(l1pt);
        if (*l1pt == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        err = paging_create_vnode(st, ObjType_VNode_AARCH64_l1, &st->cap_l0, &l0entry->cap,
                l0_idx, &l0entry->cap_mapping);
        if (err_is_fail(err)) {
            debug_printf("paging_create_vnode ObjType_VNode_AARCH64_l1 failed: %s\n", err_getstring(err));
            return err;
        }
        collections_hash_insert(st->l0pt, l0_idx, l0entry);
    }

    // mapping l1 -> l2
    const uint16_t l1_idx = VMSAv8_64_L1_INDEX(vaddr);
    struct pt_entry *l1entry = collections_hash_find(l0entry->pt, l1_idx);
    if (l1entry == NULL) {
        l1entry = paging_slab_alloc(sizeof(struct pt_entry));
        if (l1entry == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        collections_hash_table **l2pt = &l1entry->pt;
        create_hashtable(l2pt);
        if (*l2pt == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        err = paging_create_vnode(st, ObjType_VNode_AARCH64_l2, &l0entry->cap, &l1entry->cap,
                                  l1_idx, &l1entry->cap_mapping);
        if (err_is_fail(err)) {
            debug_printf("paging_create_vnode ObjType_VNode_AARCH64_l2 failed: %s\n", err_getstring(err));
            return err;
        }
        collections_hash_insert(l0entry->pt, l1_idx, l1entry);
    }

    // mapping l2 -> l3
    const uint16_t l2_idx = VMSAv8_64_L2_INDEX(vaddr);
    struct pt_l2_entry *l2entry = collections_hash_find(l1entry->pt, l2_idx);
    if (l2entry == NULL) {
        // TODO size of pt_l2_entry
        //l2entry = paging_slab_alloc(sizeof(struct pt_l2_entry));
        l2entry = paging_slab_alloc(PTABLE_ENTRIES * 8 + 64);
        if (l2entry == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        err = paging_create_vnode(st, ObjType_VNode_AARCH64_l3, &l1entry->cap, &l2entry->cap,
                                  l2_idx, &l2entry->cap_mapping);
        if (err_is_fail(err)) {
            debug_printf("paging_create_vnode ObjType_VNode_AARCH64_l3 failed: %s\n", err_getstring(err));
            return err;
        }
        collections_hash_insert(l1entry->pt, l2_idx, l2entry);
    }
    *ret_l2entry = l2entry;

    return SYS_ERR_OK;
}

// do mapping on a single lvl3 page table
static inline
errval_t do_paging_map_fixed_attr(struct paging_state *st, lvaddr_t vaddr,
                                  struct capref frame, size_t pte_count, size_t bytes,
                                          int flags, struct paging_region* ret_region) {
    errval_t err;

    struct pt_l2_entry *l2entry;
    err = paging_create_pd(st, vaddr, &l2entry);
    if (err_is_fail(err)) {
        debug_printf("paging_create_pd failed: %s\n", err_getstring(err));
        return err;
    }
    assert(l2entry != NULL);
    const uint16_t l3_idx = VMSAv8_64_L3_INDEX(vaddr);

    l2entry->l3_entries[l3_idx] = ret_region; // TODO: is this useful, store regions in here even if whole mappings spawns multipe tables
    err = st->slot_alloc->alloc(st->slot_alloc, &ret_region->cap_mapping);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc failed: %s\n", err_getstring(err));
        return err;
    }

    // TODO: offset != 0? possible

    err = vnode_map(l2entry->cap, frame, l3_idx, flags, 0, pte_count, ret_region->cap_mapping);
    if (err_is_fail(err)) {
        debug_printf("vnode_map failed: %s\n", err_getstring(err));
        err_push(err, LIB_ERR_VNODE_MAP);
        goto error_recovery;
    }

    ret_region->frame_cap = frame;
    ret_region->base_addr = vaddr;
    ret_region->current_addr = vaddr;
    ret_region->flags = flags;
    ret_region->region_size = bytes;

#ifdef CONFIG_PAGING_DEBUG
    ensure_correct_pagetable_mapping(st, vaddr);
#endif

    return SYS_ERR_OK;

    error_recovery:
    st->slot_alloc->free(st->slot_alloc, ret_region->cap_mapping);
    return err;
}

/**
 * \brief map a user provided frame at user provided VA.
 * TODO(M1): Map a frame assuming all mappings will fit into one last level pt
 * TODO(M2): General case
 */
errval_t paging_map_fixed_attr(struct paging_state *st, lvaddr_t vaddr,
                               struct capref frame, size_t bytes, int flags)
{
    errval_t err;
    debug_printf("paging_map_fixed_attr(st=%p, vaddr=%"PRIxLVADDR", bytes=%zu...)\n", st, vaddr, bytes);

    if (bytes == 0) {
        return LIB_ERR_PAGING_SIZE_INVALID;
    }
    if ((bytes % BASE_PAGE_SIZE) != 0) {
        return LIB_ERR_PAGING_SIZE_INVALID;
    }

    struct vaddr_region *vaddr_region = NULL;
    err = alloc_vaddr_region(st, vaddr, bytes, &vaddr_region);
    if (err_is_fail(err)) { return err; }

    /* how many lvl3 mappings needed in total */
    int64_t pte_count = ROUND_UP(bytes, BASE_PAGE_SIZE) / BASE_PAGE_SIZE;

    struct paging_region *next_region = NULL;
    struct paging_region *head_region = NULL;

    while (pte_count > 0) {
        /* find how many remaining entries in current lvl 3 pagetable
         * for a single call of do_paging_map_fixed_attr */
        const int64_t l3pt_idx = VMSAv8_64_L3_INDEX(vaddr);
        const int64_t free_entries_pt = 0x1FF - l3pt_idx + 1;
        int64_t curr_pte_count = 0;
        if (pte_count <= free_entries_pt) {
            curr_pte_count = pte_count;
        } else {
            curr_pte_count = free_entries_pt;
        }

        struct paging_region *paging_region =
                paging_slab_alloc(sizeof(struct paging_region));
        if (paging_region == NULL) {
            // TODO unmap everything on error (extension)
            return LIB_ERR_MALLOC_FAIL;
        }

        if (next_region == NULL) {
            next_region = paging_region;
            head_region = paging_region;
        } else {
            next_region->next = paging_region;
            next_region = paging_region;
        }

//        debug_printf("vaddr: %p, l3pt_idx: %p, pte_count: %d, free_entries_pt: %d, curr_pte_count: %d, bytes: %p\n",
//                     vaddr, l3pt_idx, pte_count, free_entries_pt, curr_pte_count, bytes);

       err = do_paging_map_fixed_attr(st, vaddr, frame, curr_pte_count, curr_pte_count * BASE_PAGE_SIZE, flags,
                                      paging_region);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "do_paging_map_fixed_attr failed\n");
            return err;
            // TODO: undo mappings on error?
            // TODO free all slots on error
        }

        pte_count = pte_count - curr_pte_count;
        vaddr += curr_pte_count * BASE_PAGE_SIZE;
    }
    vaddr_region->region = head_region;
    return err;
}

/**
 * \brief unmap a user provided frame, and return the VA of the mapped
 *        frame in `buf`.
 * NOTE: Implementing this function is optional.
 */
errval_t paging_unmap(struct paging_state *st, const void *region)
{
    return SYS_ERR_OK;
}
