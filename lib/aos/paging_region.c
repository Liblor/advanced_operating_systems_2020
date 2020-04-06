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

    struct sanitized_range range;

    err = paging_sanitize_range(base, size, &range);
    if (err_is_fail(err)) {
        return err;
    }

    pr->capc = range->size / BASE_PAGE_SIZE;
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

    err = range_tracker_add(&pr->rt, range->base, range->size, NULL);
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
    size_t size,
    void **retbuf,
    size_t *ret_size
)
{
    errval_t err;

    DEBUG_BEGIN;

    assert(pr != NULL);
    assert(retbuf != NULL);

    const size_t sanitized_size;

    err = paging_sanitize_size(size, &sanitized_size)
    if (err_is_fail(err)) {
        return err;
    }

    struct rtnode *node = NULL;

    err = range_tracker_alloc_aligned(&pr->rt, sanitized_size, BASE_PAGE_SIZE, &node);
    if (err_is_fail(err)) {
        debug_printf("range_tracker_alloc_aligned() failed: %s\n", err_getstring(err));
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

    struct sanitized_range range;

    err = paging_sanitize_range(base, bytes, &range);
    if (err_is_fail(err)) {
        return err;
    }

    struct rtnode *node;

    // TODO: Calling range_tracker_get() by a followed range_tracker_free()
    // where we pass the base does not look efficient. The region will be
    // iterated twice. We should either be able to pass the node directly for
    // freeing, or not have to get the node in the first place.
    err = range_tracker_get(&pr->rt, base, bytes, &node);
    if (err_is_fail(err)) {
        debug_printf("range_tracker_get() failed: %s\n", err_getstring(err));
        return err;
    }

    // TODO: This is not generalized yet. The caller may unmap mappings that
    // span over multiple nodes in the range tracker. Unfortunately, the range
    // tracker does not support such complex behavior at the point of writing.
    err = range_tracker_free(&pr->rt, node->base, node->size, NULL)
    if (err_is_fail(err)) {
        debug_printf("range_tracker_free() failed: %s\n", err_getstring(err));
        return err;
    }

    // TODO: Unmap installed pages.

    return SYS_ERR_OK;
}
