#include <stdint.h>
#include <string.h>

#include <collections/range_tracker.h>
#include <aos/debug.h>

// TODO Change errors
// TODO Should the ensure threshold be called in here?

static inline void check_rt_valid_state(struct range_tracker *rt)
{
#ifndef NDEBUG
    struct rtnode *current;
    for (current = rt->head->next; current != &rt->rt_tail; current = current->next) {
        assert(current->size != 0);
        assert(current->next != NULL);
        assert(current->prev != NULL);
        assert(current->prev->next == current);
        assert(current->next->prev == current);
        assert(rt->head == &rt->rt_head);
    }
#endif
}

static inline bool is_properly_aligned_range(
    struct range_tracker *rt,
    const uint64_t base,
    const uint64_t size
)
{
    assert(rt != NULL);

    if (rt->alignment == 0) {
        return true;
    }

    if (size == 0) {
        return false;
    }

    if (base % rt->alignment != 0) {
        return false;
    }

    const uint64_t end = base + size;

    // Check for overflow.
    if (end < base || end < size) {
        return false;
    }

    if (end % rt->alignment != 0) {
        return false;
    }

    return true;
}

static inline bool is_properly_aligned_size(
    struct range_tracker *rt,
    const uint64_t size
)
{
    return is_properly_aligned_range(rt, 0, size);
}

errval_t range_tracker_init_aligned(
    struct range_tracker *rt,
    struct slab_allocator *slabs,
    const uint64_t alignment
)
{
    assert(rt != NULL);
    assert(slabs != NULL);
    assert(slabs->blocksize == sizeof(struct rtnode));

    rt->slabs = slabs;
    rt->head = &rt->rt_head;
    rt->rt_head.next = &rt->rt_tail;
    rt->rt_head.prev = NULL;
    rt->rt_tail.prev = &rt->rt_head;
    rt->rt_tail.next = NULL;
    rt->alignment = alignment;

    return SYS_ERR_OK;
}

errval_t range_tracker_init(
    struct range_tracker *rt,
    struct slab_allocator *slabs
)
{
    return range_tracker_init_aligned(rt, slabs, 0);
}

errval_t range_tracker_add(
    struct range_tracker *rt,
    const uint64_t base,
    const uint64_t size,
    union range_tracker_shared shared
)
{
    errval_t err;

    assert(rt != NULL);

    if (!is_properly_aligned_range(rt, base, size)) {
        return COLLECTIONS_RANGETRACKER_ALIGNMENT;
    }

    struct rtnode *next;

    for (next = rt->head->next; next != &rt->rt_tail; next = next->next) {
        if (next->base == base)
            return MM_ERR_ALREADY_PRESENT;
        else if (next->base > base)
            break;
    }

    struct rtnode *node = slab_alloc(rt->slabs);
    if (node == NULL)
        return MM_ERR_MM_ADD;

    node->type = RangeTracker_NodeType_Free;
    node->original_region_base = base;
    node->base = base;
    node->size = size;
    node->shared = shared;

    // Add the new node into the linked list.
    // [next->prev] <--> [node] <--> [next]

    next->prev->next = node;
    node->prev = next->prev;
    next->prev = node;
    node->next = next;

    err = slab_ensure_threshold(rt->slabs, 32);
    if (err_is_fail(err))
        return err;

    check_rt_valid_state(rt);
    return SYS_ERR_OK;
}

static errval_t split_node(
    struct range_tracker *rt,
    struct rtnode *node,
    uint64_t offset,
    uint64_t size,
    enum range_tracker_nodetype new_type,
    struct rtnode **retnode
)
{
    errval_t err;

    assert(rt != NULL);
    assert(node != NULL);
    assert(node->size >= size + offset);

    if (!is_properly_aligned_range(rt, node->base + offset, size)) {
        return COLLECTIONS_RANGETRACKER_ALIGNMENT;
    }

    uint64_t old_base = node->base;
    uint64_t old_size = node->size;
    uint64_t new_base = old_base + offset;
    uint64_t new_size = size;

    /*
     * We have to split the node and mark the requested part as being
     * allocated. This will result in the following layout.
     * [node->prev] <--> [padding] <--> [node] <--> [leftover] <--> [node-next]
     */

    struct rtnode *leftover = NULL;

    // Make sure we can allocate a node for leftover if needed.
    // Only create a leftover node if there is space left.
    if (offset + size < old_size) {
        leftover = slab_alloc(rt->slabs);
        if (leftover == NULL) {
            err = MM_ERR_MM_ADD;
            goto error_recovery;
        }
    }

    struct rtnode *padding = NULL;

    // Make sure we can allocate a node for padding if needed.
    // Only create a padding node if padding is necessary.
    if (offset > 0) {
        padding = slab_alloc(rt->slabs);
        if (padding == NULL) {
            err = MM_ERR_MM_ADD;
            goto error_recovery;
        }
    }

    if (leftover != NULL) {
        leftover->original_region_base = node->original_region_base;

        // TODO Should shared really always be inherited?
        leftover->shared = node->shared;
        leftover->type = RangeTracker_NodeType_Free;
        leftover->base = old_base + offset + size;
        leftover->size = old_size - offset - size;

        node->next->prev = leftover;
        leftover->next = node->next;
        node->next = leftover;
        leftover->prev = node;
    }

    if (padding != NULL) {
        padding->original_region_base = node->original_region_base;

        // TODO Should shared really always be inherited?
        padding->shared = node->shared;
        padding->type = RangeTracker_NodeType_Free;
        padding->base = old_base;
        padding->size = offset;

        node->prev->next = padding;
        padding->prev = node->prev;
        node->prev = padding;
        padding->next = node;
    }

    node->base = new_base;
    node->size = new_size;
    node->type = new_type;

    // Sanity checks
    assert(node->size == size);
    assert(leftover == NULL || node->next->size == old_base + old_size - (new_base + new_size));
    assert(leftover == NULL || node->next->base == new_base + new_size);
    assert(padding == NULL || node->prev->size == offset);
    assert(padding == NULL || node->prev->base == old_base);
    assert(node->prev->next == node);
    assert(node->next->prev == node);
    check_rt_valid_state(rt);

    if (retnode != NULL) {
        *retnode = node;
    }

    return SYS_ERR_OK;

 error_recovery:
    if (leftover != NULL) {
        slab_free(rt->slabs, leftover);
    }

    if (padding != NULL) {
        // GCC says that the variable might be uninitialized. That cannot be
        // the case, since it is initialized as NULL, and set using
        // slab_alloc().
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
        slab_free(rt->slabs, padding);
#pragma GCC diagnostic pop
    }

    return err;
}

errval_t range_tracker_alloc_aligned(
    struct range_tracker *rt,
    uint64_t size,
    uint64_t alignment,
    struct rtnode **retnode
)
{
    errval_t err;

    assert(rt != NULL);
    assert(size != 0);
    assert(alignment != 0);

    if (!is_properly_aligned_size(rt, size)) {
        return COLLECTIONS_RANGETRACKER_ALIGNMENT;
    }

    struct rtnode *node = NULL;
    uint64_t padding_size;

    err = range_tracker_get(rt, size, alignment, &node, &padding_size);
    if (err_is_fail(err)) {
        return err;
    }

    err = split_node(rt, node, padding_size, size, RangeTracker_NodeType_Used, retnode);
    if (err_is_fail(err)) {
        return err;
    }

    // We refill at the very end, so all other mandatory tasks are already done
    // in case of any error.
    err = slab_ensure_threshold(rt->slabs, 32);
    if (err_is_fail(err)) {
        return err;
    }

    // If no error is returned the returned node must not be NULL.
    assert(node != NULL);

#ifndef NDEBUG
    struct rtnode *check_node;
    err = range_tracker_get_fixed(rt, node->base, 1, &check_node);
    assert(err_no(err) == SYS_ERR_OK);
    assert(node == check_node);
    assert(range_tracker_is_used(check_node));
#endif

    check_rt_valid_state(rt);
    return SYS_ERR_OK;
}

errval_t range_tracker_alloc_fixed(
    struct range_tracker *rt,
    const uint64_t base,
    const uint64_t size,
    struct rtnode **retnode
)
{
    errval_t err;

    assert(rt != NULL);
    assert(retnode != NULL);

    if (!is_properly_aligned_range(rt, base, size)) {
        return COLLECTIONS_RANGETRACKER_ALIGNMENT;
    }

    struct rtnode *node;
    err = range_tracker_get_fixed(rt, base, size, &node);
    if (err_is_fail(err)) {
        return err;
    }

    // TODO Maybe return error if there is not enough space

    uint64_t offset = base - node->base;

    err = split_node(rt, node, offset, size, RangeTracker_NodeType_Used, retnode);
    if (err_is_fail(err)) {
        return err;
    }

    assert((*retnode)->type == RangeTracker_NodeType_Used);

#ifndef NDEBUG
    struct rtnode *check_node;
    err = range_tracker_get_fixed(rt, base, 1, &check_node);
    assert(err_no(err) == SYS_ERR_OK);
    assert(node == check_node);
    assert(range_tracker_is_used(check_node));
#endif

    check_rt_valid_state(rt);
    return SYS_ERR_OK;
}

/*
 * Merge the node with its neighbors. This is necessary so fragmentation does
 * not lead to smaller and smaller chunks of memory. We can only merge with a
 * neighbor if
 * - the neighbor is not head or tail of our list,
 * - the neighbor is free, and
 * - the node and the neighbor stem from the same original region.
 */
static inline void range_tracker_merge_neighbors(
    struct range_tracker *rt,
    struct rtnode *node
)
{
    assert(rt != NULL);
    assert(node != NULL);

    // Merge the node with right neighbor if possible.
    if (node->next != &rt->rt_tail &&
        node->next->type == RangeTracker_NodeType_Free &&
        node->original_region_base == node->next->original_region_base) {

        struct rtnode *old = node->next;
        node->size += node->next->size;
        node->next->next->prev = node;
        node->next = node->next->next;
        slab_free(rt->slabs, old);
    }

    // Merge the node with left neighbor if possible.
    if (node->prev != &rt->rt_head &&
        node->prev->type == RangeTracker_NodeType_Free &&
        node->original_region_base == node->prev->original_region_base) {

        struct rtnode *old = node->prev;
        node->base = node->prev->base;
        node->size += node->prev->size;
        node->prev->prev->next = node;
        node->prev = node->prev->prev;
        slab_free(rt->slabs, old);
    }
}

/*
 * Free all nodes in the specified range. This function does not check if all
 * nodes in the range are allocated prior to starting with the free.
 */
static errval_t range_tracker_free_unchecked(
    struct range_tracker *rt,
    const uint64_t base,
    const uint64_t size,
    struct range_tracker_closure closure
)
{
    assert(rt != NULL);

    if (!is_properly_aligned_range(rt, base, size)) {
        return COLLECTIONS_RANGETRACKER_ALIGNMENT;
    }

    const uint64_t end = base + size;

    struct rtnode *node;

    /*
     * Free all nodes in the specified range.
     */

    for (node = rt->head->next; node != &rt->rt_tail; node = node->next) {
        if (node->base + node->size > end) {
            break;
        } else if (node->base < base) {
            continue;
        }

        range_tracker_free_cb_t free_cb = (range_tracker_free_cb_t) closure.handler;

        if (free_cb != NULL) {
            free_cb(closure.arg, node->shared, node->base, node->size);
        }

        // Free the node.
        node->type = RangeTracker_NodeType_Free;
        range_tracker_merge_neighbors(rt, node);
    }

    return SYS_ERR_OK;
}

static inline uint64_t range_tracker_get_base(
    struct range_tracker *rt
)
{
    assert(rt != NULL);

    return rt->head->next->base;
}

static inline uint64_t range_tracker_get_size(
    struct range_tracker *rt
)
{
    assert(rt != NULL);

    const uint64_t from = range_tracker_get_base(rt);
    const uint64_t to = rt->rt_tail.prev->base + rt->rt_tail.prev->size;

    return to - from;
}

errval_t range_tracker_free_all(
    struct range_tracker *rt,
    struct range_tracker_closure closure
)
{
    errval_t err;

    assert(rt != NULL);

    const uint64_t from = range_tracker_get_base(rt);
    const uint64_t size = range_tracker_get_size(rt);

    err = range_tracker_free_unchecked(rt, from, size, closure);
    if (err_is_fail(err)) {
        return err;
    }

    check_rt_valid_state(rt);
    return SYS_ERR_OK;
}

errval_t range_tracker_free(
    struct range_tracker *rt,
    const uint64_t base,
    const uint64_t size,
    struct range_tracker_closure closure
)
{
    errval_t err;

    assert(rt != NULL);

    if (!is_properly_aligned_range(rt, base, size)) {
        return COLLECTIONS_RANGETRACKER_ALIGNMENT;
    }

    const uint64_t end = base + size;

    struct rtnode *node;

    /*
     * First check if all nodes in the specified range are allocated.
     */

    for (node = rt->head->next; node != &rt->rt_tail; node = node->next) {
        if (node->base + node->size > end) {
            break;
        } else if (node->base < base) {
            continue;
        }

        if (!range_tracker_is_used(node)) {
            // TODO: Change this error code to "Cannot free unused nodes".
            return SYS_ERR_NOT_IMPLEMENTED;
        }
    }

    // TODO: Split the ends of the specified range if necessary.

    /*
     * Free all nodes in the specified range.
     */

    err = range_tracker_free_unchecked(rt, base, size, closure);
    if (err_is_fail(err)) {
        return err;
    }

    check_rt_valid_state(rt);
    return SYS_ERR_OK;
}

/*
 * Retrieve a free node with a minimum specified size and alignment.
 */
errval_t range_tracker_get(
    struct range_tracker *rt,
    uint64_t size,
    uint64_t alignment,
    struct rtnode **retnode,
    uint64_t *retpadding
)
{
    assert(rt != NULL);
    assert(size != 0);
    assert(alignment != 0);
    assert(retnode != NULL);

    if (!is_properly_aligned_size(rt, size)) {
        return COLLECTIONS_RANGETRACKER_ALIGNMENT;
    }

    struct rtnode *best = NULL;

    // Find the largest node that is still free and can hold the requested size.
    for (struct rtnode *next = rt->head->next; next != &rt->rt_tail; next = next->next) {
        assert(next != NULL);

        uint64_t padding_size = (next->base % alignment > 0) ? (alignment - (next->base % alignment)) : 0;

        // We only care about free nodes.
        if (next->type != RangeTracker_NodeType_Free)
            continue;

        // We only care about nodes of sufficient size. We also need to make
        // sure that the addition does not overflow.
        if (size + padding_size >= size && next->size < size + padding_size)
            continue;

        // We want the largest node possible to minimize fragmentation (worst-fit).
        if (best == NULL || next->size >= best->size) {
            best = next;

            if (retpadding != NULL) {
                *retpadding = padding_size;
            }
        }
    }

    if (best == NULL) {
        // TODO: Fix this error code.
        return MM_ERR_OUT_OF_MEMORY;
    }

    *retnode = best;

    check_rt_valid_state(rt);
    return SYS_ERR_OK;
}

/*
 * Retrieve the node that includes the specified range.
 */
// TODO: Remove size parameter (careful, some callers depend on that size check).
errval_t range_tracker_get_fixed(
    struct range_tracker *rt,
    const uint64_t base,
    const uint64_t size,
    struct rtnode **retnode
)
{
    assert(rt != NULL);
    assert(size != 0);
    assert(retnode != NULL);

    // Check for overflow.
    // TODO: Introduce a new error code.
    if (base + size < base) {
        return MM_ERR_NOT_FOUND;
    }

    struct rtnode *node = NULL;
    struct rtnode *current;

    for (current = rt->head->next; current != &rt->rt_tail; current = current->next) {
        if (current->base <= base && current->base + current->size >= base + size) {
            node = current;
            break;
        }

        if (current->base > base) {
            break;
        }
    }

    if (node == NULL) {
        return MM_ERR_NOT_FOUND;
    }

    *retnode = node;

    check_rt_valid_state(rt);
    return SYS_ERR_OK;
}

static void print_rtnodes(
    struct range_tracker *rt
)
{
    if (rt->head == NULL) {
        debug_printf("        [empty list]\n");
        return;
    }

    struct rtnode *current = rt->head;
    struct rtnode *last = rt->head;

    while (current != NULL) {
        debug_printf(
            "%s%p <- %p -> %p (base=%p, last=%p, size=%llu)\n",
            current->type == RangeTracker_NodeType_Used ? "       *" : "        ",
            current->prev, current, current->next, current->base,
            current->base + current->size - 1, current->size
        );

        if (current->next == NULL)
            last = current;

        current = current->next;
    }
}

void range_tracker_print_state(
    struct range_tracker *rt
)
{
    debug_printf("        HEAD ADDRESS: %p\n", &rt->rt_head);
    debug_printf("        TAIL ADDRESS: %p\n", &rt->rt_tail);

    print_rtnodes(rt);
}
