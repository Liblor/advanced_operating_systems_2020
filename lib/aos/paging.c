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
 * \param pdir Reference to the cap of the L1 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state(struct paging_state *st, lvaddr_t start_vaddr,
                           struct capref pdir, struct slot_allocator *ca)
{
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.

    st->slot_alloc = ca;
    st->cap_l0 = pdir;
    struct paging_region *pr = malloc(sizeof(struct paging_region));
    add_region(st, start_vaddr, 0xffffffffffff, pr);
    return SYS_ERR_OK;
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
 * \param pdir Reference to the cap of the L1 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state_foreign(struct paging_state *st, lvaddr_t start_vaddr,
                           struct capref pdir, struct slot_allocator *ca)
{
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    paging_init_state(st, VADDR_OFFSET, pdir, get_default_slot_allocator());
    return SYS_ERR_OK;
}

/**
 * \brief This function initializes the paging for this domain
 * It is called once before main.
 */
errval_t paging_init(void)
{
    debug_printf("paging_init\n");

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
    // TODO (M4): setup exception handler for thread `t'.
}

/**
 * \brief Initialize a paging region in `pr`, such that it  starts
 * from base and contains size bytes.
 */
errval_t paging_region_init_fixed(struct paging_state *st, struct paging_region *pr,
                                  lvaddr_t base, size_t size, paging_flags_t flags)
{
    pr->base_addr = (lvaddr_t)base;
    pr->current_addr = pr->base_addr;
    pr->region_size = size;
    pr->flags = flags;

    //Add the region to a datastructure and ensure paging_alloc
    //will return non-overlapping regions.
    struct vaddr_region *ret;
    errval_t err = alloc_vaddr_region(st, pr->base_addr, size, &ret);
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
    /**
     * TODO(M2): Implement this function
     * \brief Find a bit of free virtual address space that is large enough to
     *        accomodate a buffer of size `bytes`.
     */

    *buf = NULL;
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
    // Refill the two-level slot allocator without causing a page-fault
    return SYS_ERR_OK;
}

static inline errval_t paging_create_vnode(struct paging_state *st, enum objtype type, struct capref *parent,
        struct capref *ret, const uint16_t index, struct capref *mapping)
{
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


// create pd entry consisting of caps for mapping and child shadow page table
// TODO: use this instead of paging_create_pd
__attribute__((unused))
static inline
errval_t paging_create_pd_entry (struct paging_state *st, enum objtype type, collections_hash_table *parent_pt,
        struct capref *parent_cap, const uint16_t idx, struct pt_entry **lookup) {
    errval_t err;
    const uint64_t hashmap_buckets = 1024; // TODO decide on bucket size

    struct pt_entry *entry = collections_hash_find(parent_pt, idx);
    if (entry == NULL) {
        entry = malloc(sizeof(struct pt_entry));
        if (entry == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        collections_hash_table **entry_pt = &entry->pt;
        collections_hash_create_with_buckets(entry_pt, hashmap_buckets, NULL);
        if (*entry_pt == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        err = paging_create_vnode(st, type, parent_cap, &entry->cap,
                                  idx, &entry->cap_mapping);
        if (err_is_fail(err)) {
            debug_printf("paging_create_vnode failed: %s\n", err_getstring(err));
            return err;
        }
        collections_hash_insert(*entry_pt, idx, entry);
    }
    *lookup = entry;
    return SYS_ERR_OK;
}



// create paging directory
static inline errval_t paging_create_pd(struct paging_state *st, const lvaddr_t vaddr, struct pt_l3_entry **l3entry)
{
    assert(st != NULL);
    errval_t err;

    const uint64_t hashmap_buckets = 1024; // TODO decide on bucket size

    if (st->l0pt == NULL) {
        collections_hash_create_with_buckets(&st->l0pt, hashmap_buckets, NULL);
        if (st->l0pt == NULL ) {
            return LIB_ERR_MALLOC_FAIL;
        }
    }

    // mapping l0 -> l1
    const uint16_t l0_idx = VMSAv8_64_L0_INDEX(vaddr);
    struct pt_entry *l0entry = collections_hash_find(st->l0pt, l0_idx);
    if (l0entry == NULL) {
        l0entry = malloc(sizeof(struct pt_entry));
        if (l0entry == NULL) {
            // TODO: do we recover from alloc errors with free of resources?
            return LIB_ERR_MALLOC_FAIL;
        }
        collections_hash_table **l1pt = &l0entry->pt;
        collections_hash_create_with_buckets(l1pt, hashmap_buckets, NULL);
        if (*l1pt == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        err = paging_create_vnode(st, ObjType_VNode_AARCH64_l1, &st->cap_l0, &l0entry->cap,
                l0_idx, &l0entry->cap_mapping);
        if (err_is_fail(err)) {
            debug_printf("paging_create_vnode failed: %s\n", err_getstring(err));
            return err;
        }
        collections_hash_insert(*l1pt, l0_idx, l0entry);
    }

    // mapping l1 -> l2
    const uint16_t l1_idx = VMSAv8_64_L1_INDEX(vaddr);
    struct pt_entry *l1entry = collections_hash_find(l0entry->pt, l1_idx);
    if (l1entry == NULL) {
        l1entry = malloc(sizeof(struct pt_entry));
        if (l1entry == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        collections_hash_table **l2pt = &l1entry->pt;
        collections_hash_create_with_buckets(&l0entry->pt, hashmap_buckets, NULL);
        if (*l2pt == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        err = paging_create_vnode(st, ObjType_VNode_AARCH64_l2, &l0entry->cap, &l1entry->cap,
                                  l1_idx, &l1entry->cap_mapping);
        if (err_is_fail(err)) {
            debug_printf("paging_create_vnode failed: %s\n", err_getstring(err));
            return err;
        }
        collections_hash_insert(*l2pt, l1_idx, l1entry);
    }

    // mapping l2 -> l3
    const uint16_t l2_idx = VMSAv8_64_L2_INDEX(vaddr);
    struct pt_entry *l2entry = collections_hash_find(l1entry->pt, l2_idx);
    if (l2entry == NULL) {
        l2entry = malloc(sizeof(struct pt_entry));
        if (l2entry == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        collections_hash_table **l3pt = &l2entry->pt;
        collections_hash_create_with_buckets(l3pt, hashmap_buckets, NULL);
        if (*l3pt == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        err = paging_create_vnode(st, ObjType_VNode_AARCH64_l3, &l1entry->cap, &l2entry->cap,
                                  l2_idx, &l2entry->cap_mapping);
        if (err_is_fail(err)) {
            debug_printf("paging_create_vnode failed: %s\n", err_getstring(err));
            return err;
        }
        collections_hash_insert(*l3pt, l2_idx, l2entry);
    }

    const uint16_t l3_idx = VMSAv8_64_L3_INDEX(vaddr);
    *l3entry = collections_hash_find(l2entry->pt, l3_idx);
    if (*l3entry == NULL) {
        *l3entry = malloc(sizeof(struct pt_l3_entry));
        if (*l3entry == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        memset(*l3entry, 0, sizeof(struct pt_l3_entry));
    }
    return SYS_ERR_OK;
}

/**
 * \brief map a user provided frame at user provided VA.
 * TODO(M1): Map a frame assuming all mappings will fit into one last level pt
 * TODO(M2): General case
 */
errval_t paging_map_fixed_attr(struct paging_state *st, lvaddr_t vaddr,
                               struct capref frame, size_t bytes, int flags)
{
    assert(st != NULL);
    errval_t err;

    debug_printf("paging_map_fixed_attr(st=%p, vaddr=%"PRIxLVADDR", ...)\n", st, vaddr);

    if (bytes == 0) {
        return LIB_ERR_PAGING_SIZE_INVALID;
    } else if ((bytes % BASE_PAGE_SIZE) != 0) {
        return LIB_ERR_PAGING_SIZE_INVALID;
    }

    struct vaddr_region *region = NULL;
    err = alloc_vaddr_region(st, vaddr, bytes, &region);
    if (err_is_fail(err)) { return err; }

    struct capref l3pd;

    struct pt_l3_entry *l3entry;
    err = paging_create_pd(st, vaddr, &l3entry);
    if (err_is_fail(err)) {
        debug_printf("paging_create_pd failed: %s\n", err_getstring(err));
        return err;
    }

    assert(l3entry->entries[VMSAv8_64_L3_INDEX(vaddr)] == NULL);

    struct capref mapping;
    err = st->slot_alloc->alloc(st->slot_alloc, &mapping);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc failed: %s\n", err_getstring(err));
        return err;
    }

    err = vnode_map(l3pd, frame, l3_idx, flags, 0, pte_count, mapping);
    if (err_is_fail(err)) {
        debug_printf("vnode_map failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_VNODE_MAP);
    }

    st->is_mapped[l2_idx][l3_idx] = true;

    return SYS_ERR_OK;
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
