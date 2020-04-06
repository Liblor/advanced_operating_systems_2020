#include <aos/paging_region.h>

static inline errval_t paging_region_init_region(
    struct paging_region *pr,
    lvaddr_t base,
    size_t size,
    paging_flags_t flags
)
{
    errval_t err;

    pr->flags = flags;

    const size_t end = base + size;
    const size_t actual_base = ROUND_DOWN(base, BASE_PAGE_SIZE);
    const size_t end_base = ROUND_UP(end, BASE_PAGE_SIZE);

    assert(actual_base <= base);
    assert(end_base >= base);

    pr->capc = (end_base - actual_base) / BASE_PAGE_SIZE;
    pr->capv = calloc(pr->capc, sizeof(struct capref));

    if (pr->capv == NULL) {
        debug_printf("calloc() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_MALLOC_FAIL);
    }

    err = range_tracker_init(&pr->rt, &st->slabs);
    if (err_is_fail(err)) {
        debug_printf("range_tracker_init() failed\n");
        return err;
    }

    err = range_tracker_add(&pr->rt, base, size, NULL);
    if (err_is_fail(err)) {
        debug_printf("range_tracker_add() failed\n");
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t _paging_region_init(
    struct paging_state *st,
    struct paging_region *pr,
    lvaddr_t base,
    size_t size,
    size_t alignment,
    paging_flags_t flags,
    bool fixed
)
{
    errval_t err;

    assert(st != NULL);
    assert(pr != NULL);

    assert(!fixed || base == 0);
    assert(fixed || alignment == 0);

    DEBUG_BEGIN;

    if ((fixed && base % BASE_PAGE_SIZE != 0) ||
        (!fixed && alignment % BASE_PAGE_SIZE != 0)) {
        debug_printf("_paging_region_init() failed: Paging region must be page aligned!\n");
        return LIB_ERR_PAGING_VADDR_NOT_ALIGNED;
    }

    err = slab_ensure_threshold(&st->rt->slabs, 16);
    if (err_is_fail(err)) {
        return err;
    }

    if (fixed) {
        err = range_tracker_alloc_fixed(st->rt, base, size, NULL);
        if (err_is_fail(err)) {
            debug_printf("range_tracker_alloc_fixed() failed: Paging region must be unmapped!\n");
            return err;
        }
    } else {
        err = range_tracker_alloc_aligned(st->rt, size, alignment, NULL);
        if (err_is_fail(err)) {
            debug_printf("range_tracker_alloc_aligned() failed: Paging region must be unmapped!\n");
            return err;
        }
    }

    err = paging_region_init_region(pr, base, size, flags, node);
    if (err_is_fail(err)) {
        debug_printf("paging_region_init_region() failed: ?!\n");
        return err;
    }

    return SYS_ERR_OK;
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
    return _paging_region_init(st, pr, base, size, 0, flags, true);
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
    return _paging_region_init(st, pr, 0, size, alignment, flags, false);
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

    if (ret_size != NULL) {
        *ret_size = new_node->size;
    }

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
