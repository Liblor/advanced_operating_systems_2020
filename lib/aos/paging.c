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
#include <aos/morecore.h>

static struct paging_state current;

// TODO: check that addr is in valid stack bounds of current thread or
// TODO: check that addr is in valid heap bounds
static errval_t paging_handler(enum exception_type type, int subtype, void *addr, arch_registers_state_t *regs)
{
    errval_t err;
    lvaddr_t vaddr = ROUND_DOWN((lvaddr_t)addr, BASE_PAGE_SIZE);
    struct paging_state *st = get_current_paging_state();

    if (vaddr == 0) {
        debug_printf("NULL pointer dereferenced!\n");
        return AOS_ERR_PAGING_NULL_DEREF;
    }
    if (vaddr < st->head->base_addr) {
        debug_printf("PAGE FAULT: Address 0x%lx is not mapped or managed by parent\n", vaddr);
        return AOS_ERR_PAGING_ADDR_NOT_MANAGED;
    }
    if (!is_vaddr_page_reserved(st, vaddr)) {
        print_vaddr_regions(get_current_paging_state());
        debug_printf("PAGE FAULT: Address 0x%lx is not mapped\n", vaddr);
        return LIB_ERR_PMAP_NOT_MAPPED;
    }

    // create frame and map it
    struct capref frame;
    size_t size;
    slab_ensure_threshold(&st->slabs, 10);

    err = frame_alloc(&frame, BASE_PAGE_SIZE, &size);
    if (err_is_fail(err)) {
        debug_printf("Page fault handler error: frame_alloc failed, while "
                     "lazily mapping 0x%lx\n", vaddr);
        debug_printf("%s\n", err_getstring(err));
        return err;
    }

    if (size < BASE_PAGE_SIZE) {
        debug_printf("Page fault handler error: frame_alloc returned a too small frame "
                     "while lazily mapping 0x%lx\n", vaddr);
        debug_printf("%s\n", err_getstring(err));
        return err;
    }

    err = paging_map_fixed(st, vaddr, frame, size);
    if (err_is_fail(err)) {
        debug_printf("Page fault handler error: mapping frame failed "
                     "while lazily mapping 0x%lx\n", vaddr);
        debug_printf("%s\n", err_getstring(err));
        return err;
    }

    return SYS_ERR_OK;
}

static void
exception_handler_giveup(errval_t err, enum exception_type type, int subtype,
        void *addr, arch_registers_state_t *regs)
{
    debug_printf("\n%.*s.%d: unrecoverable error (errmsg: '%s', type: 0x%"
                               PRIxPTR", subtype: 0x%" PRIxPTR ") on %" PRIxPTR " at IP %" PRIxPTR "\n",
             DISP_NAME_LEN, disp_name(), disp_get_current_core_id(), err_getstring(err), type, subtype, addr, regs->named.pc);


    debug_print_save_area(regs);
    // debug_dump(regs); // print stack
    thread_exit(THREAD_UNRECOVERABLE_PAGEFAULT_CODE);
}

static void exception_handler(enum exception_type type, int subtype, void *addr, arch_registers_state_t *regs)
{
    // debug_printf("exception_handler(type=%d, subtype=%d, addr=%p, regs=%p)\n", type, subtype, addr, regs);

    errval_t err = SYS_ERR_OK;
    morecore_enable_static();

    switch (type) {
        case EXCEPT_PAGEFAULT:
            err = paging_handler(type, subtype, addr, regs);
            break;
        default:
            err = AOS_ERR_PAGING_INVALID_UNHANDLED_EXCEPTION;
            debug_printf("Unknown exception type\n");
    }

    morecore_enable_dynamic();

    if (err_is_fail(err)) {
        // we die here ... RIP
        exception_handler_giveup(err, type, subtype, addr, regs);
    }
}

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

    thread_mutex_init(&st->mutex);

    add_region(st, start_vaddr, 0xffffffffffff-start_vaddr, NULL);
    return SYS_ERR_OK;
}

static inline
void create_hashtable(collections_hash_table **hashmap) {
    collections_hash_create_with_buckets(hashmap, PAGING_HASHMAP_BUCKETS, NULL);
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
 * \param cap_l0 Reference to the cap of the L0 VNode.
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
    paging_init_state(st, start_vaddr, cap_l0, ca);
    return SYS_ERR_OK;
}

/**
 * \brief This function initializes the paging for this domain
 * It is called once before main.
 */
errval_t paging_init(void)
{
    errval_t err;

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
    err = paging_init_state(&current, VADDR_OFFSET, pdir, get_default_slot_allocator());
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_init_state() failed\n");
        return err_push(err, LIB_ERR_PAGING_INITIALIZATION);
    }

    set_current_paging_state(&current);

    // TIP: Think about the fact that later on, you'll have to make sure that
    // you can handle page faults in any thread of a domain.

    char *exception_stack_top = (char *) current.exception_stack_base + sizeof(current.exception_stack_base);

    err = thread_set_exception_handler(exception_handler, NULL,
            current.exception_stack_base, exception_stack_top, NULL, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "thread_set_exception_handler() failed\n");
        return err_push(err, LIB_ERR_THREAD_SET_EXCEPTION_HANDLER);
    }

    return SYS_ERR_OK;
}

/**
 * \brief Initialize per-thread paging state
 */
void paging_init_onthread(struct thread *t)
{
    DEBUG_BEGIN;
    morecore_enable_static();
    void *stack = malloc(PAGING_EXCEPTION_STACK_SIZE);

    morecore_enable_dynamic();
    void *stack_top = stack + PAGING_EXCEPTION_STACK_SIZE;

    t->exception_stack = stack;
    t->exception_stack_top = stack_top;
    t->exception_handler = exception_handler;
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

    // TODO: Add the region to a datastructure and ensure paging_alloc
    // will return non-overlapping regions.
    // Currently this function is not called directly, that's why this doesn't result in a bug.
    // It is only called by paging_region_init_aligned, we already "reserve" the vaddr_regions
    // there, but this should be rewritten.

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

    // TODO
    // split vaddr_region if necessary
    // split paging_region or keep track by other means?
    // how to keep track of mappings?
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
    errval_t err;

    DEBUG_BEGIN;

    *buf = NULL;

    err = slab_ensure_threshold(&st->slabs, 22);
    if (err_is_fail(err)) {
        return err;
    }

    thread_mutex_lock_nested(&st->mutex);
    err = reserve_vaddr_region(st, buf, bytes, alignment);
    thread_mutex_unlock(&st->mutex);
    if (err_is_fail(err)) {
        return err;
    }

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
    errval_t err;

    DEBUG_BEGIN;

    // TODO(M2): Implement me (done, remove todo after review)
    // - Call paging_alloc to get a free virtual address region of the requested size
    // - Map the user provided frame at the free virtual address

    err = slab_ensure_threshold(&st->slabs, 12);
    if (err_is_fail(err)) {
        return err;
    }

    err = paging_alloc(st, buf, bytes, BASE_PAGE_SIZE);
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
    assert(!capref_is_null(l3_entry->cap_mapping[l3_entry->num_caps - 1]));
}

static inline errval_t
paging_create_pd_level(
    struct paging_state *st,
    enum objtype type,
    const struct capref parent,
    const uint16_t index,
    const size_t size,
    collections_hash_table *ht,
    void **ret_entry
)
{
    errval_t err;

    assert(st != NULL);
    assert(ret_entry != NULL);
    assert(ht != NULL);

    const int flags = VREGION_FLAGS_READ_WRITE;

    *ret_entry = NULL;

    void *entry = collections_hash_find(ht, index);

    if (entry == NULL) {
        struct capref cap;
        struct capref cap_mapping;

        err = pt_alloc(st, type, &cap);
        if (err_is_fail(err)) {
            debug_printf("pt_alloc() failed: %s\n", err_getstring(err));
            return err_push(err, LIB_ERR_VNODE_CREATE);
        }

        err = st->slot_alloc->alloc(st->slot_alloc, &cap_mapping);
        if (err_is_fail(err)) {
            debug_printf("slot_alloc() failed: %s\n", err_getstring(err));
            return err;
        }

        /*
        error_cleanup:
        st->slot_alloc->free(st->slot_alloc, *ret);
        st->slot_alloc->free(st->slot_alloc, *cap_mapping);
        */

        entry = collections_hash_find(ht, index);
        if (entry == NULL) {
            entry = malloc(size);
            if (entry == NULL) {
                // TODO: Do we recover from alloc errors with free of resources?
                return LIB_ERR_MALLOC_FAIL;
            }

            if (type == ObjType_VNode_AARCH64_l3) {
                struct pt_l2_entry *typed_entry = (struct pt_l2_entry *) entry;
                typed_entry->cap = cap;
                typed_entry->cap_mapping = cap_mapping;
            } else {
                struct pt_entry *typed_entry = (struct pt_entry *) entry;

                create_hashtable(&typed_entry->pt);
                if (typed_entry->pt == NULL) {
                    return LIB_ERR_MALLOC_FAIL;
                }

                typed_entry->cap = cap;
                typed_entry->cap_mapping = cap_mapping;
            }

            err = vnode_map(parent, cap, index, flags, 0, 1, cap_mapping);
            if (err_is_fail(err)) {
                debug_printf("vnode_map failed: %s\n", err_getstring(err));
                return err_push(err, LIB_ERR_VNODE_MAP);
            }

            collections_hash_insert(ht, index, entry);
        }
    }

    *ret_entry = entry;

    return SYS_ERR_OK;
}

// create paging directory
static inline errval_t paging_create_pd(struct paging_state *st, const lvaddr_t vaddr, struct pt_l2_entry **ret_l2entry)
{
    errval_t err;

    assert(vaddr % BASE_PAGE_SIZE == 0);

    *ret_l2entry = NULL;

    if (st->l0pt == NULL) {
        create_hashtable(&st->l0pt);
        if (st->l0pt == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
    }

    // Mapping l0 -> l1
    const uint16_t l0_idx = VMSAv8_64_L0_INDEX(vaddr);
    struct pt_entry *l0entry;
    err = paging_create_pd_level(
        st,
        ObjType_VNode_AARCH64_l1,
        st->cap_l0,
        l0_idx,
        sizeof(struct pt_entry),
        st->l0pt,
        (void **) &l0entry
    );
    if (err_is_fail(err)) {
        debug_printf("paging_create_pd_level() failed: %s\n", err_getstring(err));
        return err;
    }

    // Mapping l1 -> l2
    const uint16_t l1_idx = VMSAv8_64_L1_INDEX(vaddr);
    struct pt_entry *l1entry;
    err = paging_create_pd_level(
        st,
        ObjType_VNode_AARCH64_l2,
        l0entry->cap,
        l1_idx,
        sizeof(struct pt_entry),
        l0entry->pt,
        (void **) &l1entry
    );
    if (err_is_fail(err)) {
        debug_printf("paging_create_pd_level() failed: %s\n", err_getstring(err));
        return err;
    }

    // Mapping l2 -> l3
    const uint16_t l2_idx = VMSAv8_64_L2_INDEX(vaddr);
    struct pt_l2_entry *l2entry;
    err = paging_create_pd_level(
        st,
        ObjType_VNode_AARCH64_l3,
        l1entry->cap,
        l2_idx,
        sizeof(struct pt_l2_entry),
        l1entry->pt,
        (void **) &l2entry
    );
    if (err_is_fail(err)) {
        debug_printf("paging_create_pd_level() failed: %s\n", err_getstring(err));
        return err;
    }

    *ret_l2entry = l2entry;

    return SYS_ERR_OK;
}

/** map a single lvl3 page table into page table directory */
static inline
errval_t paging_map_fixed_single_pt3(struct paging_state *st, lvaddr_t vaddr,
                                     struct capref frame, size_t pte_count, size_t bytes,
                                     int flags, uint64_t offset, struct paging_region* ret_region) {
    errval_t err;

    assert(vaddr % BASE_PAGE_SIZE == 0);
    assert(bytes % BASE_PAGE_SIZE == 0);

    struct pt_l2_entry *l2entry;
    err = paging_create_pd(st, vaddr, &l2entry);
    if (err_is_fail(err)) {
        debug_printf("paging_create_pd failed: %s\n", err_getstring(err));
        return err;
    }
    assert(l2entry != NULL);
    const uint16_t l3_idx = VMSAv8_64_L3_INDEX(vaddr);

    uint64_t curr_idx = ret_region->num_caps;
    l2entry->l3_entries[l3_idx] = ret_region;
    err = st->slot_alloc->alloc(st->slot_alloc, &ret_region->cap_mapping[curr_idx]);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc failed: %s\n", err_getstring(err));
        return err;
    }

    err = vnode_map(l2entry->cap, frame, l3_idx, flags, offset, pte_count, ret_region->cap_mapping[curr_idx]);

    if (err_is_fail(err)) {
        debug_printf("vnode_map failed: %s\n", err_getstring(err));
        err_push(err, LIB_ERR_VNODE_MAP);
        goto error_recovery;
    }

    ret_region->frame_cap = frame;
    ret_region->num_caps++;

#ifdef CONFIG_PAGING_DEBUG
    ensure_correct_pagetable_mapping(st, vaddr);
#endif

    return SYS_ERR_OK;

    error_recovery:
    st->slot_alloc->free(st->slot_alloc, ret_region->cap_mapping[curr_idx]);
    return err;
}

/**
 * \brief map a user provided frame at user provided VA.
 *
 * Assumptions:
 * - caller must pass vaddr which is base page aligned.
 * - bytes may not be base page aligned.
 *
 */
errval_t paging_map_fixed_attr(struct paging_state *st, lvaddr_t vaddr,
                               struct capref frame, size_t bytes, int flags)
{
    errval_t err;
    //debug_printf("paging_map_fixed_attr(st=%p, vaddr=%"PRIxLVADDR", ..., bytes=%zx, ...)\n", st, vaddr, bytes);
    thread_mutex_lock_nested(&st->mutex);

    // run on vmem which does not pagefault
    bool is_dynamic = !get_morecore_state()->heap_static;
    morecore_enable_static();

    if (bytes == 0) {
        return LIB_ERR_PAGING_SIZE_INVALID;
    }
    if (vaddr % BASE_PAGE_SIZE != 0) {
        return LIB_ERR_PAGING_VADDR_NOT_ALIGNED;
    }
    bytes = ROUND_UP(bytes, BASE_PAGE_SIZE);

    struct vaddr_region *vaddr_region = NULL;
    err = alloc_vaddr_region(st, vaddr, bytes, &vaddr_region);
    if (err_is_fail(err)) {
        return err;
    }

    err = slab_ensure_threshold(&st->slabs, 12);
    if (err_is_fail(err)) {
        return err;
    }

    /* how many lvl3 mappings needed in total */
    uint64_t pte_count = ROUND_UP(bytes, BASE_PAGE_SIZE) / BASE_PAGE_SIZE;
    /* Upper bound on how many different level 3 pages we need
     * the +2 is to account for a not full level 3 before and a not full level 3 table after */
    const uint64_t upper_bound_single_lvl3 = pte_count / VMSAv8_64_PTABLE_NUM_ENTRIES + 2;
    uint64_t offset = 0;

    struct paging_region *paging_region = malloc(sizeof(struct paging_region));
    if (paging_region == NULL) {
        // TODO free vaddr_region
        return LIB_ERR_MALLOC_FAIL;
    }
    paging_region->cap_mapping = malloc(upper_bound_single_lvl3 * sizeof(struct capref));
    if (paging_region->cap_mapping == NULL) {
        // TODO free vaddr_region
        return LIB_ERR_MALLOC_FAIL;
    }
    paging_region->base_addr = vaddr;
    paging_region->current_addr = paging_region->base_addr;
    paging_region->region_size = bytes;
    paging_region->flags = flags;
    paging_region->num_caps = 0;
    vaddr_region->region = paging_region;

    while (pte_count > 0) {
        assert (paging_region->num_caps < upper_bound_single_lvl3);
        /* find how many remaining entries in current lvl 3 pagetable
         * for a single call of paging_map_fixed_single_pt3 */
        const uint64_t l3pt_idx = VMSAv8_64_L3_INDEX(vaddr);
        const uint64_t free_entries_pt = MASK(VMSAv8_64_PTABLE_BITS) - l3pt_idx + 1;
        uint64_t curr_pte_count = 0;
        if (pte_count <= free_entries_pt) {
            curr_pte_count = pte_count;
        } else {
            curr_pte_count = free_entries_pt;
        }

        err = paging_map_fixed_single_pt3(st, vaddr, frame, curr_pte_count, curr_pte_count * BASE_PAGE_SIZE, flags,
                                          offset, paging_region);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "paging_map_fixed_single_pt3 failed\n");
            return err;
            // TODO: undo mappings on error?
            // TODO free all slots on error
        }

        pte_count = pte_count - curr_pte_count;
        vaddr += curr_pte_count * BASE_PAGE_SIZE;
        offset += curr_pte_count * BASE_PAGE_SIZE;
    }
    if (is_dynamic) {
        morecore_enable_dynamic();
    }
    thread_mutex_unlock(&st->mutex);
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
