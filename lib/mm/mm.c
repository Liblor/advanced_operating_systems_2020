/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

#include <stdint.h>
#include <string.h>

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>
#include <aos/cap_predicates.h>

errval_t mm_init(struct mm *mm,
                 enum objtype objtype,
                 slab_refill_func_t slab_refill_func,
                 slot_alloc_t slot_alloc_func,
                 slot_refill_t slot_refill_func,
                 void *slot_alloc_inst)
{
    assert(mm != NULL);
    assert(slot_alloc_func != NULL);
    assert(slot_refill_func != NULL);

    if (slab_refill_func == NULL)
        slab_refill_func = slab_default_refill;

    mm->slot_alloc = slot_alloc_func;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc_inst = slot_alloc_inst;
    mm->objtype = objtype;

    // NOTE: The slab is later grown by the initial process.
    slab_init(&mm->slabs, sizeof(struct mmnode), slab_refill_func);

    mm->head = &mm->mm_head;
    mm->mm_head.next = &mm->mm_tail;
    mm->mm_head.prev = NULL;
    mm->mm_tail.prev = &mm->mm_head;
    mm->mm_tail.next = NULL;

    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm)
{
    assert(!"NYI");
}

static void print_mmnodes(struct mm *mm) {
    if (mm->head == NULL) {
        debug_printf("        [empty list]\n");
    } else {
        struct mmnode *current = mm->head;
        struct mmnode *last = mm->head;

        while (current != NULL) {
            debug_printf("%s%p <- %p -> %p (base=%p, last=%p, size=%u)\n", current->type == NodeType_Allocated ? "       *" : "        ", current->prev, current, current->next, current->base, current->base + current->size - 1, current->size);
            if (current->next == NULL)
                last = current;
            current = current->next;
        }
    }
}

void mm_print_state(struct mm *mm) {
    print_mmnodes(mm);
}

errval_t mm_add(struct mm *mm, struct capref cap, genpaddr_t base, size_t size)
{
    assert(mm != NULL);

    errval_t err;

    struct mmnode *next;
    for (next = mm->head->next; next != &mm->mm_tail; next = next->next) {
        if (next->base == base)
            return MM_ERR_ALREADY_PRESENT;
        else if (next->base > base)
            break;
    }

    struct mmnode *node = slab_alloc(&mm->slabs);
    if (node == NULL)
        return MM_ERR_MM_ADD;

    node->type = NodeType_Free;
    node->cap.cap = cap;
    node->cap.base = base;
    node->cap.size = size;
    node->base = base;
    node->size = size;

    // Add the new node into the linked list.
    // [next->prev] <--> [node] <--> [next]

    next->prev->next = node;
    node->prev = next->prev;
    next->prev = node;
    node->next = next;

    err = slab_ensure_threshold(&mm->slabs, 10);
    if (err_is_fail(err))
        return err;

    return SYS_ERR_OK;
}

errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap)
{
    assert(mm != NULL);

    errval_t err;

    if (size == 0)
        return MM_ERR_INVALID_SIZE;

    if (alignment == 0 || alignment % BASE_PAGE_SIZE != 0)
        return MM_ERR_INVALID_ALIGNMENT;

    struct mmnode *best = NULL;
    size_t best_size = 0;
    size_t best_padding_size = 0;

    // Find the largest node that is still free and can hold the requested size.
    for (struct mmnode *next = mm->head->next; next != &mm->mm_tail; next = next->next) {
        size_t padding_size = (next->base % alignment > 0) ? (alignment - (next->base % alignment)) : 0;

        // We only care about free nodes.
        if (next->type != NodeType_Free)
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

    const genpaddr_t best_base = best->base;

    /*
     * We have to split the node and mark the requested part as being
     * allocated. This will result in the following layout.
     * [best->prev] <--> [padding] <--> [best] <--> [leftover] <--> [best-next]
     */

    struct mmnode *leftover = NULL;

    // Make sure we can allocate a node for leftover if needed.
    // Only create a leftover node if there is space left.
    if (best_padding_size + size < best_size) {
        leftover = slab_alloc(&mm->slabs);
        if (leftover == NULL) {
            err = MM_ERR_MM_ADD;
            goto error_recovery;
        }
    }

    struct mmnode *padding = NULL;

    // Make sure we can allocate a node for padding if needed.
    // Only create a padding node if padding is necessary.
    if (best_padding_size > 0) {
        padding = slab_alloc(&mm->slabs);
        if (padding == NULL) {
            err = MM_ERR_MM_ADD;
            goto error_recovery;
        }
    }

    best->type = NodeType_Allocated;
    best->base = best_base + best_padding_size;
    best->size = size;

    if (leftover != NULL) {
        leftover->cap = best->cap;
        leftover->type = NodeType_Free;
        leftover->base = best_base + best_padding_size + size;
        leftover->size = best_size - best_padding_size - size;

        best->next->prev = leftover;
        leftover->next = best->next;
        best->next = leftover;
        leftover->prev = best;
    }

    if (padding != NULL) {
        padding->cap = best->cap;
        padding->type = NodeType_Free;
        padding->base = best_base;
        padding->size = best_padding_size;

        best->prev->next = padding;
        padding->prev = best->prev;
        best->prev = padding;
        padding->next = best;
    }

    // Retype the aligned part of the node with the requested size.
    err = mm->slot_alloc(mm->slot_alloc_inst, 1, retcap);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_SLOT_ALLOC);
        goto error_recovery;
    }

    err = cap_retype(*retcap, best->cap.cap, best_base + best_padding_size - best->cap.base, mm->objtype, size, 1);
    if (err_is_fail(err)) {
        // TODO: Is this the right error code?
        err = err_push(err, LIB_ERR_CAP_RETYPE);

        // We have to throw away potential erros, since the main reason for
        // failure is the failed retyping.
        slot_free(*retcap);

        goto error_recovery;
    }

    // The slot refilling happens after retyping, since this way the caller
    // gets their memory block but knows that subsequent calls might fail.
    err = mm->slot_refill(mm->slot_alloc_inst);
    if (err_is_fail(err)) {
        return err_push(err, MM_ERR_SLOT_REFILL);
    }

    // We refill at the very end, so all other mandatory tasks are already done
    // in case of any error.
    err = slab_ensure_threshold(&mm->slabs, 10);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;

error_recovery:
    if (leftover != NULL) {
        slab_free(&mm->slabs, leftover);
    }

    if (padding != NULL) {
        // GCC says that the variable might be uninitialized. That cannot be
        // the case, since it is initialized as NULL, and set using
        // slab_alloc().
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
        slab_free(&mm->slabs, padding);
        #pragma GCC diagnostic pop
    }

    return err;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}

errval_t mm_free(struct mm *mm, struct capref cap, genpaddr_t base, gensize_t size)
{
    assert(mm != NULL);

    errval_t err;

    struct mmnode *node;

    for (node = mm->head->next; node != &mm->mm_tail; node = node->next) {
        // We can only free allocated nodes.
        if (node->type != NodeType_Allocated)
            continue;

        // The sizes must match.
        if (node->size != size)
            continue;

        if (node->base == base)
            break;
    }

    if (node == &mm->mm_tail)
        return MM_ERR_NOT_FOUND;

    // TODO: Revoke the capability to prevent further use.
    //err = cap_revoke(cap);
    //if (err_is_fail(err))
    //    return err_push(err, MM_ERR_MM_FREE);

    // TODO: Make use of cap_destroy() here.
    // TODO Maybe use an explicit error for NULL_CAP.
    err = cap_delete(cap);
    if (err_is_fail(err))
        return err_push(err, LIB_ERR_CAP_DELETE);

    err = slot_free(cap);
    if (err_is_fail(err))
        return err_push(err, LIB_ERR_SLOT_FREE);

    node->type = NodeType_Free;

    /*
     * Next, we need to merge the node with its neighbors. This is necessary so
     * fragmentation does not lead to smaller and smaller chunks of memory. We
     * can only merge with a neighbor if
     * - the neighbor is not head or tail of our list,
     * - the neighbor is free, and
     * - the node and the neighbor origin from the same root capability that
     *   was initially passed from the kernel.
     */

    // Merge the node with next neighbor if possible.
    if (node->next != &mm->mm_tail &&
        node->next->type == NodeType_Free &&
        node->cap.base == node->next->cap.base) {

        struct mmnode *old = node->next;
        node->size += node->next->size;
        node->next->next->prev = node;
        node->next = node->next->next;
        slab_free(&mm->slabs, old);
    }

    // Merge the node with previous neighbor if possible.
    if (node->prev != &mm->mm_head &&
        node->prev->type == NodeType_Free &&
        node->cap.base == node->prev->cap.base) {

        struct mmnode *old = node->prev;
        node->base = node->prev->base;
        node->size += node->prev->size;
        node->prev->prev->next = node;
        node->prev = node->prev->prev;
        slab_free(&mm->slabs, old);
    }

    return SYS_ERR_OK;
}
