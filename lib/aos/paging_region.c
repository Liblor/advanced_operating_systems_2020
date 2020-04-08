#include <aos/debug.h>
#include <aos/paging_region.h>

static inline errval_t paging_region_init_region(
    struct paging_state *st,
    struct paging_region *pr,
    const lvaddr_t base,
    const size_t size,
    const paging_flags_t flags,
    struct rtnode *node,
    const bool implicit
)
{
    errval_t err;

    pr->flags = flags;

    PAGING_CHECK_RANGE(base, size);

    pr->node = node;
    pr->implicit = implicit;

    err = range_tracker_init_aligned(&pr->rt, &st->slabs, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        debug_printf("range_tracker_init_aligned() failed\n");
        return err;
    }

    err = range_tracker_add(&pr->rt, base, size, (union range_tracker_shared) NULL);
    if (err_is_fail(err)) {
        debug_printf("range_tracker_add() failed\n");
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t _paging_region_init(
    struct paging_state *st,
    struct paging_region *pr,
    const lvaddr_t base,
    const size_t size,
    const size_t alignment,
    const paging_flags_t flags,
    const bool fixed,
    const bool implicit
)
{
    errval_t err;

    assert(st != NULL);
    assert(pr != NULL);
    assert(fixed || base == 0);
    assert(!fixed || alignment == 0);

    if ((fixed && base % BASE_PAGE_SIZE != 0) ||
        (!fixed && alignment % BASE_PAGE_SIZE != 0)) {
        debug_printf("_paging_region_init() failed: Paging region must be page aligned!\n");
        return LIB_ERR_PAGING_VADDR_NOT_ALIGNED;
    }

    err = slab_ensure_threshold(&st->slabs, 16);
    if (err_is_fail(err)) {
        return err;
    }

    memset(pr, 0x00, sizeof(struct paging_region));

    struct rtnode *node;
    struct rtnode *check_node;

    if (fixed) {
        err = range_tracker_alloc_fixed(&st->rt, base, size, &node);
        if (err_is_fail(err)) {
            debug_printf("range_tracker_alloc_fixed() failed: Paging region must be unmapped!\n");
            return err;
        }
        err = range_tracker_get_fixed(&st->rt, base, 1, &check_node);
        assert(err_no(err) == SYS_ERR_OK);
    } else {
        err = range_tracker_alloc_aligned(&st->rt, size, alignment, &node);
        if (err_is_fail(err)) {
            debug_printf("range_tracker_alloc_aligned() failed: Paging region must be unmapped!\n");
            return err;
        }
        err = range_tracker_get_fixed(&st->rt, node->base, 1, &check_node);
        assert(err_no(err) == SYS_ERR_OK);
    }

    assert(node == check_node);

    err = paging_region_init_region(st, pr, node->base, node->size, flags, node, implicit);
    if (err_is_fail(err)) {
        debug_printf("paging_region_init_region() failed: ?!\n");
        return err;
    }

    node->shared.ptr = pr;

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
    DEBUG_BEGIN;

    return _paging_region_init(st, pr, base, size, 0, flags, true, false);
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
    DEBUG_BEGIN;

    return _paging_region_init(st, pr, 0, size, alignment, flags, false, false);
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
    DEBUG_BEGIN;

    return paging_region_init_aligned(st, pr, size, BASE_PAGE_SIZE, flags);
}

/**
 * \brief Return a pointer to a bit of the paging region `pr`.
 * This function gets used in some of the code that is responsible
 * for allocating Frame (and other) capabilities.
 */
errval_t paging_region_map(
    struct paging_region *pr,
    size_t size,
    void **retbuf,
    size_t *ret_size
)
{
    errval_t err;

    DEBUG_BEGIN;

    assert(pr != NULL);
    assert(retbuf != NULL);
    PAGING_CHECK_SIZE(size);

    size = ROUND_UP(size, BASE_PAGE_SIZE);

    struct rtnode *node = NULL;

    err = range_tracker_alloc_aligned(&pr->rt, size, BASE_PAGE_SIZE, &node);
    if (err_is_fail(err)) {
        debug_printf("range_tracker_alloc_aligned() failed: %s\n", err_getstring(err));
        return err;
    }

    err = add_mapping_list_to_node(node);
    if (err_is_fail(err)) {
        return err;
    }

    *retbuf = (void *) node->base;

    if (ret_size != NULL) {
        *ret_size = node->size;
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
    errval_t err;

    DEBUG_BEGIN;

    assert(pr != NULL);

    bytes = ROUND_DOWN(bytes, BASE_PAGE_SIZE);

    PAGING_CHECK_RANGE(base, bytes);

    struct rtnode *node;

    // TODO: Calling range_tracker_get() by a followed range_tracker_free()
    // where we pass the base does not look efficient. The region will be
    // iterated twice. We should either be able to pass the node directly for
    // freeing, or not have to get the node in the first place.
    err = range_tracker_get(&pr->rt, base, bytes, &node, NULL);
    if (err_is_fail(err)) {
        debug_printf("range_tracker_get() failed: %s\n", err_getstring(err));
        return err;
    }

    // TODO: This is not generalized yet. The caller may unmap mappings that
    // span over multiple nodes in the range tracker. Unfortunately, the range
    // tracker does not support such complex behavior at the point of writing.
    err = range_tracker_free(&pr->rt, node->base, node->size, MKRTCLOSURE(NULL, NULL));
    if (err_is_fail(err)) {
        debug_printf("range_tracker_free() failed: %s\n", err_getstring(err));
        return err;
    }

    // TODO: Unmap installed pages.

    // TODO: Change to OK.
    return SYS_ERR_NOT_IMPLEMENTED;
}
