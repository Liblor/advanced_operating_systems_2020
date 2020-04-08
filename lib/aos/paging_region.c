#include <aos/debug.h>
#include <aos/paging_region.h>
#include <aos/capabilities.h>

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

    // Get large enough node from paging region.
    struct rtnode *mapping_node = NULL;
    // Set this to something other than 0, so we can check if it's explicitly set.
    uint64_t padding = 1;

    err = range_tracker_get(&pr->rt, size, BASE_PAGE_SIZE, &mapping_node, &padding);
    if (err_is_fail(err)) {
        debug_printf("range_tracker_get_fixed() failed: %s\n", err_getstring(err));
        return err;
    }

    assert(mapping_node != NULL);
    assert(padding == 0);

    // TODO: The following loop is very similar to the one in
    // paging_map_fixed_attr(), and could be generalized.

    /*
    err = create_mapping_nodes(st, pr, vaddr, size, node_cb);
    if (err_is_fail(err)) {
        debug_printf("create_mapping_nodes() failed: %s\n", err_getstring(err));
        return err;
    }
    */

    const lvaddr_t vaddr = mapping_node->base;
    *retbuf = (void *) vaddr;
    lvaddr_t curr_vaddr = vaddr;

    uint64_t page_count = size / BASE_PAGE_SIZE;

    while (page_count > 0) {
        // Calculate how many remaining entries there are in the current L3 pagetable.
        const uint64_t l3_idx = VMSAv8_64_L3_INDEX(curr_vaddr);
        const uint64_t free_l3_entries = PTABLE_ENTRIES - l3_idx;

        uint64_t curr_page_count = MIN(page_count, free_l3_entries);

        // Create mapping node.
        mapping_node = NULL;
        err = range_tracker_alloc_fixed(&pr->rt, curr_vaddr, curr_page_count * BASE_PAGE_SIZE, &mapping_node);
        if (err_is_fail(err)) {
            return err;
        }
        assert(mapping_node != NULL);

        struct frame_mapping_pair *mapping_pair = calloc(1, sizeof(struct frame_mapping_pair));
        if (mapping_pair == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        mapping_node->shared.ptr = mapping_pair;

        page_count = page_count - curr_page_count;
        curr_vaddr += curr_page_count * BASE_PAGE_SIZE;
    }

    if (ret_size != NULL) {
        *ret_size = mapping_node->size;
    }

    return SYS_ERR_OK;
}

static void range_tracker_free_cb(
    void *callback_state,
    union range_tracker_shared shared,
    uint64_t base,
    uint64_t size
)
{
    errval_t err;

    struct frame_mapping_pair *mapping_pair = shared.ptr;

    err = vnode_unmap(mapping_pair->pt->cap, mapping_pair->mapping);
    if (err_is_fail(err)) {
        debug_printf("vnode_unmap() failed in paging_region_unmap() callback: %s\n", err_getstring(err));
    }

    /*
     * TODO: Should we call aos_ram_free()? If so, how does it work for
     * non-init dispatchers, which have to "return" the memory to the memory
     * server.
     */

    /*
     * TODO: Do we need to revoke the capability?
     */

    err = cap_destroy(mapping_pair->frame);
    if (err_is_fail(err)) {
        debug_printf("cap_destroy() failed in paging_region_unmap() callback: %s\n", err_getstring(err));
    }
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

    err = range_tracker_free(&pr->rt, base, bytes, MKRTCLOSURE(range_tracker_free_cb, NULL));
    if (err_is_fail(err)) {
        debug_printf("range_tracker_free() failed: %s\n", err_getstring(err));
        return err;
    }

    return SYS_ERR_OK;
}

/**
 * \brief Free all mappings in this paging region.
 * If some mappings do not exist in this region, skip them.
 */
errval_t paging_region_unmap_all(
    struct paging_region *pr
)
{
    errval_t err;

    DEBUG_BEGIN;

    assert(pr != NULL);

    err = range_tracker_free_all(&pr->rt, MKRTCLOSURE(range_tracker_free_cb, NULL));
    if (err_is_fail(err)) {
        debug_printf("range_tracker_free_all() failed: %s\n", err_getstring(err));
        return err;
    }

    return SYS_ERR_OK;
}
