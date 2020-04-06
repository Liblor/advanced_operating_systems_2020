static inline void paging_region_init_region(
    struct paging_region *pr,
    lvaddr_t base,
    size_t size,
    paging_flags_t flags,
    struct vaddr_node *node
)
{
    pr->base_addr = base;
    pr->region_size = size;
    pr->flags = flags;
    pr->head = node;
}

/**
 * \brief Initialize a paging region in `pr`, such that it  starts
 * from base and contains size bytes.
 */
errval_t paging_region_init_fixed(
    struct paging_state *st,
    struct paging_region *pr,
    lvaddr_t base,
    size_t size,
    paging_flags_t flags
)
{
    errval_t err;

    assert(st != NULL);

    DEBUG_BEGIN;

    err = slab_ensure_threshold(&st->slabs, 12);
    if (err_is_fail(err)) {
        return err;
    }

    struct vaddr_node *node;
    node = vaddr_nodes_get(st, base, size);
    if (node == NULL) {
        return LIB_ERR_PAGING_ADDR_ALREADY_MAPPED;
    }
    // Reserve the address range for the new memory region.
    err = vaddr_nodes_set_region(st, node, base, size, pr);
    if (err_is_fail(err)) {
        return err;
    }

    paging_region_init_region(pr, base, size, flags, node);

    return SYS_ERR_OK;
}

/**
 * \brief Initialize a paging region in `pr`, such that it contains at least
 * size bytes and is aligned to a multiple of alignment.
 */
errval_t paging_region_init_aligned(
    struct paging_state *st,
    struct paging_region *pr,
    size_t size,
    size_t alignment,
    paging_flags_t flags
)
{
    errval_t err;

    assert(st != NULL);

    DEBUG_BEGIN;

    err = slab_ensure_threshold(&st->slabs, 12);
    if (err_is_fail(err)) {
        return err;
    }
    // Find a free region in the virtual address space.
    struct vaddr_node *node;
    node = vaddr_nodes_get_free(st, size, alignment);
    if (node == NULL) {
        return LIB_ERR_OUT_OF_VIRTUAL_ADDR;
    }
    // Reserve the address range for the new memory region.
    err = vaddr_nodes_set_region(st, node, node->base_addr, size, pr);
    if (err_is_fail(err)) {
        return err;
    }

    paging_region_init_region(pr, node->base_addr, size, flags, node);

    return SYS_ERR_OK;
}

/**
 * \brief Initialize a paging region in `pr`, such that it contains at least
 * size bytes.
 *
 * This function gets used in some of the code that is responsible
 * for allocating Frame (and other) capabilities.
 */
errval_t paging_region_init(
    struct paging_state *st,
    struct paging_region *pr,
    size_t size,
    paging_flags_t flags
)
{
    return paging_region_init_aligned(st, pr, size, BASE_PAGE_SIZE, flags);
}

/**
 * \brief Return a pointer to a bit of the paging region `pr`.
 * This function gets used in some of the code that is responsible
 * for allocating Frame (and other) capabilities.
 */
errval_t paging_region_map(
    struct paging_region *pr,
    size_t req_size,
    void **retbuf,
    size_t *ret_size
)
{
    errval_t err;

    DEBUG_BEGIN;

    // TODO: Similar to vaddr_nodes_get_free(), could be merged.

    assert(pr != NULL);
    assert(retbuf != NULL);

    const size_t new_size = ROUND_UP(req_size, BASE_PAGE_SIZE);

    // Handle overflow.
    if (new_size < req_size) {
        return LIB_ERR_PAGING_SIZE_INVALID;
    }

    struct vaddr_node *node = pr->head;

    while (node != NULL && node->region == pr && !(vaddr_nodes_is_type(node, NodeType_Free) && node->size >= new_size)) {
        node = node->next;
    }

    if (node == NULL) {
        return LIB_ERR_VSPACE_MMU_AWARE_NO_SPACE;
    }

    struct vaddr_node *new_node = NULL;

    err = vaddr_nodes_alloc_node(get_current_paging_state(), node, node->base_addr, req_size, &new_node);
    if (err_is_fail(err)) {
        debug_printf("vaddr_nodes_alloc_node() failed\n");
        return err;
    }

    *retbuf = (void *)new_node->base_addr;
    *ret_size = new_node->size;

    return SYS_ERR_OK;
}

/**
 * \brief Free a bit of the paging region `pr`.
 * This function gets used in some of the code that is responsible
 * for allocating Frame (and other) capabilities.
 * NOTE: Implementing this function is optional.
 */
errval_t paging_region_unmap(
    struct paging_region *pr,
    lvaddr_t base,
    size_t bytes
)
{
    // XXX: should free up some space in paging region, however need to track
    //      holes for non-trivial case

    // TODO
    // split vaddr_node if necessary
    // split paging_region or keep track by other means?
    // how to keep track of mappings?
    return LIB_ERR_NOT_IMPLEMENTED;
}
