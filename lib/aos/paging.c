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
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    return LIB_ERR_NOT_IMPLEMENTED;
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
    return SYS_ERR_OK;
}

/**
 * \brief This function initializes the paging for this domain
 * It is called once before main.
 */
errval_t paging_init(void)
{
    debug_printf("paging_init\n");
    // TODO (M2): Call paging_init_state for &current
    // TODO (M4): initialize self-paging handler
    // TIP: use thread_set_exception_handler() to setup a page fault handler
    // TIP: Think about the fact that later on, you'll have to make sure that
    // you can handle page faults in any thread of a domain.
    // TIP: it might be a good idea to call paging_init_state() from here to
    // avoid code duplication.
    set_current_paging_state(&current);

    current.slot_alloc = get_default_slot_allocator();

    // M1
    current.l1_created = false;
    current.l2_created = false;
    current.last_addr = VADDR_OFFSET;
    for (size_t i = 0; i < ARMV8_PAGE_DIRECTORY_SIZE; i++) {
        current.l2_table[i].created = false;
    }
    // M1 end

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

    //TODO(M2): Add the region to a datastructure and ensure paging_alloc
    //will return non-overlapping regions.
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

    // TODO(M2): Implement me
    // - Call paging_alloc to get a free virtual address region of the requested size
    // - Map the user provided frame at the free virtual address

    return LIB_ERR_NOT_IMPLEMENTED;

}

errval_t slab_refill_no_pagefault(struct slab_allocator *slabs, struct capref frame,
                                  size_t minbytes)
{
    // Refill the two-level slot allocator without causing a page-fault
    return SYS_ERR_OK;
}

errval_t paging_map_fixed_attr(struct paging_state *st, lvaddr_t vaddr,
                               struct capref frame, size_t bytes, int flags)
{
    /**
     * \brief map a user provided frame at user provided VA.
     * TODO(M1): Map a frame assuming all mappings will fit into one last level pt
     * TODO(M2): General case
     */
    // ASSUMPTION: L0 and L1 page table are fixed, no overlapping requests
    debug_printf("paging_map_fixed_attr(vaddr: %lx, bytes: %lu )\n", vaddr, bytes);

    // L0 Page Table
    struct capref l0_pt = {
            .cnode = cnode_page,
            .slot = 0,
    };

    errval_t err;

    // L1 Page Table
    if (!st->l1_created) {
        err = pt_alloc_l1(st, &st->l1_pt);
        if (err_is_fail(err)) { return err; }
        st->l1_created = true;

        capaddr_t l0_index = FIELD(ARMV8_PAGE_L0_INDEX_OFFSET, ARMV8_PAGE_ADDRESS_BITS, vaddr);
        struct capref l0_l1_mapping;
        err = st->slot_alloc->alloc(st->slot_alloc, &l0_l1_mapping);
        if (err_is_fail(err)) {
            cap_destroy(st->l1_pt);
            return err;
        }
        err = vnode_map(l0_pt, st->l1_pt, l0_index, VREGION_FLAGS_READ_WRITE, 0, 1, l0_l1_mapping);
        if (err_is_fail(err)) {
            cap_destroy(l0_l1_mapping);
            cap_destroy(st->l1_pt);
            return err;
        }
    }

    // L2 Page Table
    //struct capref l2_pt;
    if (!st->l2_created) {
        err = pt_alloc_l2(st, &st->l2_pt);
        if (err_is_fail(err)) { return err; }
        st->l2_created = true;

        capaddr_t l1_index = FIELD(ARMV8_PAGE_L1_INDEX_OFFSET, ARMV8_PAGE_ADDRESS_BITS, vaddr);
        struct capref l1_l2_mapping;
        err = st->slot_alloc->alloc(st->slot_alloc, &l1_l2_mapping);
        if (err_is_fail(err)) {
            cap_destroy(st->l2_pt);
            return err;
        }
        err = vnode_map(st->l1_pt, st->l2_pt, l1_index, VREGION_FLAGS_READ_WRITE, 0, 1, l1_l2_mapping);
        if (err_is_fail(err)) {
            cap_destroy(l1_l2_mapping);
            cap_destroy(st->l2_pt);
            return err;
        }
    }

    // L3 Page Table
    struct capref l3_pt;
    capaddr_t l2_index = FIELD(ARMV8_PAGE_L2_INDEX_OFFSET, ARMV8_PAGE_ADDRESS_BITS, vaddr);
    if (st->l2_table[l2_index].created) {
        l3_pt = st->l2_table[l2_index].cap;
    } else {
        err = pt_alloc_l3(st, &l3_pt);
        if (err_is_fail(err)) { return err; }

        struct capref l2_l3_mapping;
        err = st->slot_alloc->alloc(st->slot_alloc, &l2_l3_mapping);
        if (err_is_fail(err)) {
            cap_destroy(l3_pt);
            return err;
        }
        err = vnode_map(st->l2_pt, l3_pt, l2_index, VREGION_FLAGS_READ_WRITE, 0, 1, l2_l3_mapping);
        if (err_is_fail(err)) {
            cap_destroy(l2_l3_mapping);
            cap_destroy(l3_pt);
            return err;
        }
        st->l2_table[l2_index].created = true;
        st->l2_table[l2_index].cap = l3_pt;
    }

    struct capref l3_frame_mapping;
    capaddr_t l3_index = FIELD(ARMV8_PAGE_L3_INDEX_OFFSET, ARMV8_PAGE_ADDRESS_BITS, vaddr);
    err = st->slot_alloc->alloc(st->slot_alloc, &l3_frame_mapping);
    if (err_is_fail(err)) { return err; }
    err = vnode_map(l3_pt, frame, l3_index, flags, vaddr & MASK(12), 1, l3_frame_mapping);
    if (err_is_fail(err)) {
        cap_destroy(l3_frame_mapping);
        return err;
    }

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
