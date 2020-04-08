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

#include <stdio.h>

#include "threads_priv.h"

static struct paging_state current;

/*
static errval_t back_vaddr(struct paging_state st, lvaddr_t vaddr) {
    errval_t err;

    assert(vaddr % BASE_PAGE_SIZE == 0);

    struct rtnode *node;
    err = range_tracker_get(st->rt, vaddr, 0, node);
    if (err_is_fail(err)) {
        return err;
    }
    struct vaddr_node *node = vaddr_nodes_get(st, (lvaddr_t) vaddr, BASE_PAGE_SIZE);

    struct paging_region *pr = (struct paging_region *) node->shared.ptr;
    if (capref_is_null(st->cap_l0)) {
    }

    // TODO Implement the rest of this function

    // create frame and map it
    struct capref frame;
    size_t size;
    slab_ensure_threshold(&st->slabs, 10);

    err = frame_alloc(&frame, BASE_PAGE_SIZE, &size);
    if (err_is_fail(err)) {
        debug_printf("Page fault handler error: frame_alloc failed, while " "lazily mapping 0x%lx\n", vaddr);
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
        debug_printf("Page fault handler error: mapping frame failed " "while lazily mapping 0x%lx\n", vaddr);
        debug_printf("%s\n", err_getstring(err));
        return err;
    }

    return SYS_ERR_OK;
}
*/

// TODO: check that addr is in valid stack bounds of current thread or
// TODO: check that addr is in valid heap bounds
static errval_t paging_handler(
    enum exception_type type,
    int subtype,
    void *addr,
    arch_registers_state_t * regs
)
{
    /*
    errval_t err;
    lvaddr_t vaddr = ROUND_DOWN((lvaddr_t) addr, BASE_PAGE_SIZE);
    struct paging_state *st = get_current_paging_state();

    if (vaddr == 0) {
        debug_printf("NULL pointer dereferenced!\n");
        return AOS_ERR_PAGING_NULL_DEREF;
    }

    if (vaddr < st->start_addr) {
        debug_printf("PAGE FAULT: Address %p is not mapped or managed by parent (base=%p)!\n", vaddr, st->start_addr);
        return AOS_ERR_PAGING_ADDR_NOT_MANAGED;
    }

    err = back_vaddr(st, vaddr);
    if (err_is_fail(err)) {
        debug_printf("PAGE FAULT: Failed to back address %p with physical memory\n", vaddr);
        DEBUG_ERR(err, "");
        return err;
    }
    */

    return SYS_ERR_OK;
}

static void exception_handler_giveup(
    errval_t err,
    enum exception_type type,
    int subtype,
    void *addr,
    arch_registers_state_t * regs
)
{
    debug_printf(
        "\n%.*s.%d: unrecoverable error (errmsg: '%s', type: 0x%" PRIxPTR ", subtype: 0x%" PRIxPTR ") on %" PRIxPTR " at IP %" PRIxPTR "\n",
         DISP_NAME_LEN, disp_name(), disp_get_current_core_id(), err_getstring(err), type, subtype, addr, regs->named.pc);

    debug_print_save_area(regs);

    // debug_dump(regs); // print stack

    thread_exit(THREAD_UNRECOVERABLE_PAGEFAULT_CODE);
}

static void exception_handler(
    enum exception_type type,
    int subtype,
    void *addr,
    arch_registers_state_t * regs
)
{
    debug_printf("exception_handler(type=%d, subtype=%d, addr=%p, regs=%p)\n", type, subtype, addr, regs);
    errval_t err = SYS_ERR_OK;

    switch (type) {
    case EXCEPT_PAGEFAULT:
        err = paging_handler(type, subtype, addr, regs);
        break;
    default:
        err = AOS_ERR_PAGING_INVALID_UNHANDLED_EXCEPTION;
        debug_printf("Unknown exception type\n");
    }

    if (err_is_fail(err)) {
        // we die here ... RIP
        exception_handler_giveup(err, type, subtype, addr, regs);
    }
}

/**
 * \brief Helper function that allocates a slot and
 *        creates a aarch64 page table capability for a certain level
 */
static errval_t pt_alloc(
    struct paging_state *st,
    enum objtype type,
    struct capref *ret
)
{
    errval_t err;

    DEBUG_BEGIN;

    assert(st != NULL);

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

/**
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
errval_t paging_init_state(
    struct paging_state *st,
    lvaddr_t start_vaddr,
    struct capref cap_l0,
    struct slot_allocator *ca
)
{
    errval_t err;

    assert(st != NULL);

    DEBUG_BEGIN;

    memset(st, 0x00, sizeof(struct paging_state));

    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    st->slot_alloc = ca;

    st->l0pt.type = ObjType_VNode_AARCH64_l0;
    st->l0pt.cap = cap_l0;
    st->l0pt.cap_mapping = NULL_CAP;
    st->l0pt.entries = NULL;

    st->start_addr = start_vaddr;

    slab_init(&st->slabs, RANGE_TRACKER_NODE_SIZE, slab_default_refill);

    slab_grow(&st->slabs, st->initial_slabs_buffer, sizeof(st->initial_slabs_buffer));

    err = range_tracker_init_aligned(&st->rt, &st->slabs, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        debug_printf("range_tracker_init_aligned() failed\n");
        return err;
    }

    err = range_tracker_add(&st->rt, start_vaddr, (1ULL << 48) - start_vaddr, (union range_tracker_shared) NULL);
    if (err_is_fail(err)) {
        debug_printf("range_tracker_add() failed\n");
        return err;
    }

    return SYS_ERR_OK;
}

static inline void create_hashtable(
    collections_hash_table **hashmap
)
{
    collections_hash_create_with_buckets(hashmap, PAGING_HASHMAP_BUCKETS, NULL);
}

/**
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
errval_t paging_init_state_foreign(
    struct paging_state *st,
    lvaddr_t start_vaddr,
    struct capref cap_l0,
    struct slot_allocator *ca
)
{
    assert(st != NULL);

    DEBUG_BEGIN;

    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.

    paging_init_state(st, start_vaddr, cap_l0, ca);

    return SYS_ERR_OK;
}

/**
 * \brief This function initializes the paging for this domain
 * It is called once before main.
 */
errval_t paging_init(
    void
)
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

    // TODO Uncomment when page fault handler is working again
    /*
    char *exception_stack_top = (char *)current.exception_stack_base + sizeof(current.exception_stack_base);

    err = thread_set_exception_handler(
        exception_handler,
        NULL,
        current.exception_stack_base,
        exception_stack_top,
        NULL,
        NULL
    );
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "thread_set_exception_handler() failed\n");
        return err_push(err, LIB_ERR_THREAD_SET_EXCEPTION_HANDLER);
    }
    */

    return SYS_ERR_OK;
}

/**
 * \brief Initialize per-thread paging state
 */
void paging_init_onthread(
    struct thread *t
)
{
    DEBUG_BEGIN;

    void *stack = malloc(PAGING_EXCEPTION_STACK_SIZE);
    if (stack == NULL) {
        debug_printf("Allocating exception stack failed\n");
        return;
    }
    void *stack_top = stack + PAGING_EXCEPTION_STACK_SIZE;

    t->exception_stack = stack;
    t->exception_stack_top = stack_top;
    t->exception_handler = exception_handler;
}

/**
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
errval_t paging_alloc(
    struct paging_state *st,
    void **buf,
    size_t bytes,
    size_t alignment
)
{
    errval_t err;

    DEBUG_BEGIN;

    assert(st != NULL);
    assert(buf != NULL);
    assert(alignment % BASE_PAGE_SIZE == 0);
    PAGING_CHECK_SIZE(bytes)

    bytes = ROUND_UP(bytes, BASE_PAGE_SIZE);

    *buf = NULL;

    err = slab_ensure_threshold(&st->slabs, 12);
    if (err_is_fail(err)) {
        return err;
    }

    struct paging_region *pr = calloc(1, sizeof(struct paging_region));

    // flags = 0, because it will not be used for implicit paging regions.
    err = paging_region_init_aligned(st, pr, bytes, alignment, 0);
    if (err_is_fail(err)) {
        return err;
    }

    pr->implicit = true;

    *buf = (void *) pr->node->base;

    assert(((lvaddr_t) *buf) % alignment == 0);

    return SYS_ERR_OK;
}

/**
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
errval_t paging_map_frame_attr(
    struct paging_state *st,
    void **buf,
    size_t bytes,
    struct capref frame,
    int flags,
    void *arg1,
    void *arg2
)
{
    errval_t err;

    DEBUG_BEGIN;

    assert(st != NULL);
    assert(buf != NULL);

    bytes = ROUND_UP(bytes, BASE_PAGE_SIZE);

    // Find a free region in the virtual address space.
    err = paging_alloc(st, buf, bytes, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err;
    }

    err = paging_map_fixed_attr(st, (lvaddr_t) *buf, frame, bytes, flags);
    if (err_is_fail(err)) {
        return err;
    }

    assert(((uint64_t) *buf) % BASE_PAGE_SIZE == 0);

    return SYS_ERR_OK;
}

errval_t slab_refill_no_pagefault(
    struct slab_allocator *slabs,
    struct capref frame,
    size_t minbytes
)
{
    DEBUG_BEGIN;
    // Refill the two-level slot allocator without causing a page-fault
    return SYS_ERR_OK;
}

__attribute__((__unused__))
static inline void ensure_correct_pagetable_mapping(
    struct paging_state *st,
    lvaddr_t vaddr,
    uint64_t page_count
)
{
    errval_t err;

    const uint16_t l0_idx = VMSAv8_64_L0_INDEX(vaddr);
    const uint16_t l1_idx = VMSAv8_64_L1_INDEX(vaddr);
    const uint16_t l2_idx = VMSAv8_64_L2_INDEX(vaddr);
    //const uint16_t l3_idx = VMSAv8_64_L3_INDEX(vaddr);

    assert(!capref_is_null(st->l0pt.cap));
    assert(capref_is_null(st->l0pt.cap_mapping));
    assert(st->l0pt.type == ObjType_VNode_AARCH64_l0);
    assert(st->l0pt.entries != NULL);

    struct page_table *l1pt = collections_hash_find(st->l0pt.entries, l0_idx);
    assert(l1pt != NULL);
    assert(!capref_is_null(l1pt->cap));
    assert(!capref_is_null(l1pt->cap_mapping));
    assert(l1pt->type == ObjType_VNode_AARCH64_l1);
    assert(l1pt->entries != NULL);

    struct page_table *l2pt = collections_hash_find(l1pt->entries, l1_idx);
    assert(l2pt != NULL);
    assert(!capref_is_null(l2pt->cap));
    assert(!capref_is_null(l2pt->cap_mapping));
    assert(l2pt->type == ObjType_VNode_AARCH64_l2);
    assert(l2pt->entries != NULL);

    struct page_table *l3pt = collections_hash_find(l2pt->entries, l2_idx);
    assert(l3pt != NULL);
    assert(!capref_is_null(l3pt->cap));
    assert(!capref_is_null(l3pt->cap_mapping));
    assert(l3pt->type == ObjType_VNode_AARCH64_l3);
    // L3 pagetable does not have other page tables as entries
    assert(l3pt->entries == NULL);

    // TODO Check if page region for the given vaddr exists.
    struct rtnode *pr_node;
    err = range_tracker_get_fixed(&st->rt, vaddr, 1, &pr_node);
    assert(err_no(err) == SYS_ERR_OK);
    debug_printf("pr_node=%p\n", pr_node);
    assert(range_tracker_is_used(pr_node));

    struct paging_region *pr = pr_node->shared.ptr;
    struct rtnode *node;
    err = range_tracker_get_fixed(&pr->rt, vaddr, 1, &node);
    assert(err_no(err) == SYS_ERR_OK);
    debug_printf("node=%p\n", node);
    assert(range_tracker_is_used(node));

    const size_t l3_region_size = BASE_PAGE_SIZE * PTABLE_ENTRIES;
    const uint64_t mapping_idx = (vaddr - ROUND_DOWN(node->base, l3_region_size)) / l3_region_size;
    struct mapping_list *mlist = node->shared.ptr;
    assert(mlist != NULL);
    debug_printf("vaddr=%u, mapping_idx=%u, total=%u\n", vaddr, mapping_idx, mlist->total);
    assert(mapping_idx < mlist->total);
    assert(mapping_idx < mlist->count);
    assert(!capref_is_null(mlist->caps[mapping_idx]));

    for (uint64_t i = 0; i < page_count; i++) {
        uint8_t *ptr = (uint8_t *) (vaddr + i * BASE_PAGE_SIZE);
        uint8_t b = *ptr;
        *ptr = 0x1A;
        *ptr = b;
    }
}

static inline errval_t get_or_create_pt_entry(
    struct paging_state *st,
    struct page_table *parent,
    const uint16_t index,
    enum objtype type,
    struct page_table **ret_entry
)
{
    errval_t err;

    DEBUG_BEGIN;

    assert(st != NULL);
    assert(ret_entry != NULL);
    assert(type != ObjType_VNode_AARCH64_l0);
    assert(type != ObjType_VNode_AARCH64_l1 || parent->type == ObjType_VNode_AARCH64_l0);
    assert(type != ObjType_VNode_AARCH64_l2 || parent->type == ObjType_VNode_AARCH64_l1);
    assert(type != ObjType_VNode_AARCH64_l3 || parent->type == ObjType_VNode_AARCH64_l2);
    assert(index < PTABLE_ENTRIES);

    const int flags = VREGION_FLAGS_READ_WRITE;

    *ret_entry = NULL;

    struct page_table *entry = collections_hash_find(parent->entries, index);

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

        entry = collections_hash_find(parent->entries, index);
        if (entry == NULL) {
            entry = malloc(sizeof(struct page_table));
            if (entry == NULL) {
                // TODO: Do we recover from alloc errors with free of resources?
                return LIB_ERR_MALLOC_FAIL;
            }

            entry->cap = cap;
            entry->cap_mapping = cap_mapping;
            entry->type = type;

            if (type == ObjType_VNode_AARCH64_l3) {
                // An L3 table doesn't have other page tables as entries.
                entry->entries = NULL;
            } else {
                create_hashtable(&entry->entries);
            }

            err = vnode_map(parent->cap, cap, index, flags, 0, 1, cap_mapping);
            if (err_is_fail(err)) {
                debug_printf("vnode_map failed: %s\n", err_getstring(err));
                return err_push(err, LIB_ERR_VNODE_MAP);
            }

            collections_hash_insert(parent->entries, index, entry);
        }
    }

    *ret_entry = entry;

    return SYS_ERR_OK;
}

// Finds and returns the L3 pagetable (which is an L2 entry) for the given virtual address. If the L3 pagetable for the given virtual address does not exist yet, it will be created.
static inline errval_t get_l3_pt(
    struct paging_state *st,
    const lvaddr_t vaddr,
    struct page_table **ret_l2_entry
)
{
    errval_t err;

    DEBUG_BEGIN;

    assert(st != NULL);
    assert(ret_l2_entry != NULL);

    *ret_l2_entry = NULL;

    struct page_table *l0pt = &st->l0pt;
    if (l0pt->entries == NULL) {
        create_hashtable(&l0pt->entries);
    }

    // Get L1 page table from L0 page table
    const uint16_t l0_idx = VMSAv8_64_L0_INDEX(vaddr);
    struct page_table *l0entry;
    err = get_or_create_pt_entry(
        st,
        &st->l0pt,
        l0_idx,
        ObjType_VNode_AARCH64_l1,
        &l0entry
    );
    if (err_is_fail(err)) {
        debug_printf("get_or_create_pt_entry() failed: %s\n", err_getstring(err));
        return err;
    }

    // Get L2 page table from L1 page table
    const uint16_t l1_idx = VMSAv8_64_L1_INDEX(vaddr);
    struct page_table *l1entry;
    err = get_or_create_pt_entry(
        st,
        l0entry,
        l1_idx,
        ObjType_VNode_AARCH64_l2,
        &l1entry
    );
    if (err_is_fail(err)) {
        debug_printf("get_or_create_pt_entry() failed: %s\n", err_getstring(err));
        return err;
    }

    // Get L3 page table from L2 page table
    const uint16_t l2_idx = VMSAv8_64_L2_INDEX(vaddr);
    struct page_table *l2entry;
    err = get_or_create_pt_entry(
        st,
        l1entry,
        l2_idx,
        ObjType_VNode_AARCH64_l3,
        &l2entry
    );
    if (err_is_fail(err)) {
        debug_printf("get_or_create_pt_entry() failed: %s\n", err_getstring(err));
        return err;
    }

    *ret_l2_entry = l2entry;

    return SYS_ERR_OK;
}

static inline errval_t map_in_l3(
    struct paging_state *st,
    struct paging_region *pr,
    struct page_table *l3pt,
    uint64_t l3_idx,
    struct capref frame,
    uint64_t frame_offset,
    uint64_t page_count,
    struct rtnode *node,
    int flags
)
{
    errval_t err;

    DEBUG_BEGIN;

    assert(st != NULL);
    assert(pr != NULL);
    assert(l3pt != NULL);
    assert(node != NULL);
    assert(l3pt->type == ObjType_VNode_AARCH64_l3);
    assert(page_count > 0);
    assert(l3_idx + page_count <= PTABLE_ENTRIES);

    struct capref mapping;

    // Allocate slot for the resulting mapping capability
    err = st->slot_alloc->alloc(st->slot_alloc, &mapping);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc failed: %s\n", err_getstring(err));
        return err;
    }

    err = vnode_map(l3pt->cap, frame, l3_idx, flags, frame_offset, page_count, mapping);
    if (err_is_fail(err)) {
        debug_printf("vnode_map failed: %s\n", err_getstring(err));
        err_push(err, LIB_ERR_VNODE_MAP);
        goto error_recovery;
    }

    struct mapping_list *mlist = node->shared.ptr;
    assert(capref_is_null(mlist->caps[mlist->count]));
    assert(mlist->count < mlist->total);
    mlist->caps[mlist->count] = mapping;
    mlist->count++;

    return SYS_ERR_OK;

 error_recovery:
    st->slot_alloc->free(st->slot_alloc, mapping);
    return err;
}

/**
 * \brief Map a user provided frame at user provided VA.
 * \param vaddr The virtual address to map the frame to. Must be page aligned.
 * \param bytes The size of the frame to be mapped. Must be page aligned.
 */
errval_t paging_map_fixed_attr(
    struct paging_state *st,
    lvaddr_t vaddr,
    struct capref frame,
    size_t bytes,
    int flags
)
{
    errval_t err;

    DEBUG_BEGIN;

    assert(st != NULL);

    bytes = ROUND_UP(bytes, BASE_PAGE_SIZE);

    PAGING_CHECK_RANGE(vaddr, bytes);

    debug_printf("paging_map_fixed_attr(st=%p, vaddr=%" PRIxLVADDR ", ..., bytes=%zx, ...)\n", st, vaddr, bytes);

    err = slab_ensure_threshold(&st->slabs, 12);
    if (err_is_fail(err)) {
        return err;
    }

    struct rtnode *node;

    err = range_tracker_get_fixed(&st->rt, vaddr, bytes, &node);
    if (err_is_fail(err)) {
        debug_printf("range_tracker_get_fixed() failed: %s\n", err_getstring(err));
        return err;
    }

    struct paging_region *pr;

    if (range_tracker_is_used(node)) {
        assert(node->shared.ptr != NULL);

        pr = node->shared.ptr;

        if (!pr->implicit) {
            // This is an explicit paging region. We don't want the user to
            // mess with it.

            return AOS_ERR_PAGING_ADDR_RESERVED;
        }
    } else {
        assert(node->shared.ptr == NULL);

        // TODO: Free this pr if subsequent error occurs.
        pr = calloc(1, sizeof(struct paging_region));
        if (pr == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }

        err = paging_region_init_fixed(st, pr, vaddr, bytes, 0);
        if (err_is_fail(err)) {
            return err;
        }

        pr->implicit = true;
    }

    struct rtnode *new_node;

    err = range_tracker_alloc_fixed(&pr->rt, vaddr, bytes, &new_node);
    if (err_is_fail(err)) {
        return err;
    }

    struct rtnode *check_node;
    err = range_tracker_get_fixed(&pr->rt, vaddr, 1, &check_node);
    assert(err_no(err) == SYS_ERR_OK);
    assert(new_node == check_node);

    assert(range_tracker_is_used(new_node));

    err = add_mapping_list_to_node(new_node);
    if (err_is_fail(err)) {
        return err;
    }
    struct mapping_list *mlist = new_node->shared.ptr;

    uint64_t page_count = bytes / BASE_PAGE_SIZE;
    uint64_t frame_offset = 0;
    lvaddr_t curr_vaddr = vaddr;

    while (page_count > 0) {
        // Calculate how many remaining entries there are in the current L3 pagetable
        const uint64_t l3_idx = VMSAv8_64_L3_INDEX(curr_vaddr);
        const uint64_t free_l3_entries = PTABLE_ENTRIES - l3_idx;

        uint64_t curr_page_count = MIN(page_count, free_l3_entries);

        mlist = new_node->shared.ptr;

        struct page_table *l3pt;
        err = get_l3_pt(st, curr_vaddr, &l3pt);
        if (err_is_fail(err)) {
            // TODO Cleanup
            return err;
        }

        mlist = new_node->shared.ptr;
        err = map_in_l3(st, pr, l3pt, l3_idx, frame, frame_offset, curr_page_count, new_node, flags);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "map_in_l3() failed\n");
            return err;
            // TODO: undo mappings and everything else on error?
            // TODO free all slots on error
        }

#ifdef CONFIG_PAGING_DEBUG
        ensure_correct_pagetable_mapping(st, curr_vaddr, curr_page_count);
#endif

        page_count = page_count - curr_page_count;
        curr_vaddr += curr_page_count * BASE_PAGE_SIZE;
        frame_offset += curr_page_count * BASE_PAGE_SIZE;
    }

    return SYS_ERR_OK;
}

/**
 * \brief unmap a user provided frame, and return the VA of the mapped
 *        frame in `buf`.
 * NOTE: Implementing this function is optional.
 */
errval_t paging_unmap(
    struct paging_state *st,
    const void *region
)
{
    assert(st != NULL);

    return SYS_ERR_NOT_IMPLEMENTED;
}
