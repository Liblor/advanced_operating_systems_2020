#include <stdint.h>
#include <string.h>

#include <collections/range_tracker.h>
#include <aos/debug.h>

// TODO Change errors
// TODO Should the ensure threshold be called in here?

errval_t range_tracker_init(struct range_tracker *rt, slab_refill_func_t slab_refill_func)
{
    assert(rt != NULL);

    if (slab_refill_func == NULL)
        slab_refill_func = slab_default_refill;

    slab_init(&rt->slabs, sizeof(struct rtnode), slab_refill_func);

    rt->head = &rt->rt_head;
    rt->rt_head.next = &rt->rt_tail;
    rt->rt_head.prev = NULL;
    rt->rt_tail.prev = &rt->rt_head;
    rt->rt_tail.next = NULL;

    return SYS_ERR_OK;
}

errval_t range_tracker_add(struct range_tracker *rt, uint64_t base, uint64_t size, union range_tracker_shared shared)
{
    assert(rt != NULL);

    errval_t err;

    struct rtnode *next;
    for (next = rt->head->next; next != &rt->rt_tail; next = next->next) {
        if (next->base == base)
            return MM_ERR_ALREADY_PRESENT;
        else if (next->base > base)
            break;
    }

    struct rtnode *node = slab_alloc(&rt->slabs);
    if (node == NULL)
        return MM_ERR_MM_ADD;

    node->type = RangeTracker_NodeType_Free;
    node->original_region_base = base;
    node->base = base;
    node->size = size;
    node->shared = shared;

    // Add the new node into the linked list.
    // [next->prev] <--> [node] <--> [next]

    // TODO Should this not be inserted in order?
    next->prev->next = node;
    node->prev = next->prev;
    next->prev = node;
    node->next = next;

    err = slab_ensure_threshold(&rt->slabs, 20);
    if (err_is_fail(err))
        return err;

    return SYS_ERR_OK;
}

static errval_t split_node(struct range_tracker *rt, struct rtnode *node, uint64_t offset, uint64_t size, struct rtnode **retnode)
{
    assert(node != NULL);
    assert(node->size >= size + offset);

    errval_t err;

    uint64_t best_base = node->base;
    uint64_t best_size = node->size;
    uint64_t best_padding_size = offset;
    struct rtnode *best = node;
    /*
     * We have to split the node and mark the requested part as being
     * allocated. This will result in the following layout.
     * [best->prev] <--> [padding] <--> [best] <--> [leftover] <--> [best-next]
     */

    struct rtnode *leftover = NULL;

    // Make sure we can allocate a node for leftover if needed.
    // Only create a leftover node if there is space left.
    if (best_padding_size + size < best_size) {
        leftover = slab_alloc(&rt->slabs);
        if (leftover == NULL) {
            err = MM_ERR_MM_ADD;
            goto error_recovery;
        }
    }

    struct rtnode *padding = NULL;

    // Make sure we can allocate a node for padding if needed.
    // Only create a padding node if padding is necessary.
    if (best_padding_size > 0) {
        padding = slab_alloc(&rt->slabs);
        if (padding == NULL) {
            err = MM_ERR_MM_ADD;
            goto error_recovery;
        }
    }

    best->type = RangeTracker_NodeType_Used;
    best->base = best_base + best_padding_size;
    best->size = size;

    if (leftover != NULL) {
        leftover->original_region_base = best->original_region_base;
        // TODO Should shared really always be inherited?
        leftover->shared = best->shared;
        leftover->type = RangeTracker_NodeType_Free;
        leftover->base = best_base + best_padding_size + size;
        leftover->size = best_size - best_padding_size - size;

        best->next->prev = leftover;
        leftover->next = best->next;
        best->next = leftover;
        leftover->prev = best;
    }

    if (padding != NULL) {
        padding->original_region_base = best->original_region_base;
        // TODO Should shared really always be inherited?
        padding->shared = best->shared;
        padding->type = RangeTracker_NodeType_Free;
        padding->base = best_base;
        padding->size = best_padding_size;

        best->prev->next = padding;
        padding->prev = best->prev;
        best->prev = padding;
        padding->next = best;
    }

    if (retnode != NULL) {
        *retnode = best;
    }

    return SYS_ERR_OK;

error_recovery:
    if (leftover != NULL) {
        slab_free(&rt->slabs, leftover);
    }

    if (padding != NULL) {
        // GCC says that the variable might be uninitialized. That cannot be
        // the case, since it is initialized as NULL, and set using
        // slab_alloc().
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
        slab_free(&rt->slabs, padding);
        #pragma GCC diagnostic pop
    }

    return err;
}

errval_t range_tracker_alloc_aligned(struct range_tracker *rt, uint64_t size, uint64_t alignment, struct rtnode **retnode)
{
    assert(rt != NULL);

    errval_t err;

    if (size == 0)
        return MM_ERR_INVALID_SIZE;

    if (alignment == 0 || alignment % BASE_PAGE_SIZE != 0)
        return MM_ERR_INVALID_ALIGNMENT;

    struct rtnode *best = NULL;
    uint64_t best_size = 0;
    uint64_t best_padding_size = 0;

    // Find the largest node that is still free and can hold the requested size.
    for (struct rtnode *next = rt->head->next; next != &rt->rt_tail; next = next->next) {
        uint64_t padding_size = (next->base % alignment > 0) ? (alignment - (next->base % alignment)) : 0;

        // We only care about free nodes.
        if (next->type != RangeTracker_NodeType_Free)
            continue;

        // We only care about nodes of sufficient size. We also need to make
        // sure that the addition does not overflow.
        if (size + padding_size >= size && next->size < size + padding_size)
            continue;

        // We want the largest node possible to minimize fragmentation (worst-fit).
        if (next->size >= best_size) {
            best = next;
            best_size = next->size;
            best_padding_size = padding_size;
        }
    }

    if (best == NULL) {
        return MM_ERR_OUT_OF_MEMORY;
    }


    err = split_node(rt, best, best_padding_size, size, retnode);
    if (err_is_fail(err)) {
        return err;
    }

    // We refill at the very end, so all other mandatory tasks are already done
    // in case of any error.
    err = slab_ensure_threshold(&rt->slabs, 20);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

errval_t range_tracker_alloc_fixed(struct range_tracker *rt, uint64_t base, uint64_t size, struct rtnode **retnode) {
    errval_t err;

    assert(base % BASE_PAGE_SIZE == 0);

    struct rtnode *node;
    err = range_tracker_get(rt, base, size, &node);
    if (err_is_fail(err)) {
        return err;
    }

    // TODO Maybe return error if there is not enough space

    uint64_t offset = base - node->base;

    err = split_node(rt, node, offset, size, retnode);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

errval_t range_tracker_free(struct range_tracker *rt, uint64_t base, uint64_t size, union range_tracker_shared *shared)
{
    assert(rt != NULL);

    struct rtnode *node;

    // TODO: See range_tracker_get() on how to optimize this loop.

    for (node = rt->head->next; node != &rt->rt_tail; node = node->next) {
        // We can only free allocated nodes.
        if (node->type != RangeTracker_NodeType_Used)
            continue;

        // The sizes must match.
        if (node->size != size)
            continue;

        if (node->base == base)
            break;
    }

    if (node == &rt->rt_tail)
        return MM_ERR_NOT_FOUND;

    node->type = RangeTracker_NodeType_Free;
    if (shared != NULL) {
        *shared = node->shared;
    }

    /*
     * Next, we need to merge the node with its neighbors. This is necessary so
     * fragmentation does not lead to smaller and smaller chunks of memory. We
     * can only merge with a neighbor if
     * - the neighbor is not head or tail of our list,
     * - the neighbor is free, and
     * - the node and the neighbor stem from the same original region
     *   was initially passed from the kernel.
     */

    // Merge the node with next neighbor if possible.
    if (node->next != &rt->rt_tail &&
        node->next->type == RangeTracker_NodeType_Free &&
        node->original_region_base == node->next->original_region_base) {

        struct rtnode *old = node->next;
        node->size += node->next->size;
        node->next->next->prev = node;
        node->next = node->next->next;
        slab_free(&rt->slabs, old);
    }

    // Merge the node with previous neighbor if possible.
    if (node->prev != &rt->rt_head &&
        node->prev->type == RangeTracker_NodeType_Free &&
        node->original_region_base == node->prev->original_region_base) {

        struct rtnode *old = node->prev;
        node->base = node->prev->base;
        node->size += node->prev->size;
        node->prev->prev->next = node;
        node->prev = node->prev->prev;
        slab_free(&rt->slabs, old);
    }

    return SYS_ERR_OK;
}

errval_t range_tracker_get(struct range_tracker *rt, uint64_t base, uint64_t size, struct rtnode **retnode)
{
    assert(rt != NULL);
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

    return SYS_ERR_OK;
}

static void print_rtnodes(struct range_tracker *rt)
{
    if (rt->head == NULL) {
        debug_printf("        [empty list]\n");
    } else {
        struct rtnode *current = rt->head;
        struct rtnode *last = rt->head;

        while (current != NULL) {
            debug_printf("%s%p <- %p -> %p (base=%p, last=%p, size=%u)\n", current->type == RangeTracker_NodeType_Used ? "       *" : "        ", current->prev, current, current->next, current->base, current->base + current->size - 1, current->size);
            if (current->next == NULL)
                last = current;
            current = current->next;
        }
    }
}

void range_tracker_print_state(struct range_tracker *rt)
{
    print_rtnodes(rt);
}
