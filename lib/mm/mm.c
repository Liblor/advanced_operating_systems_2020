/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>



static void print_mmnodes(struct mm *mm) {
    if (mm->head == NULL) {
        printf("        [empty list]\n");
    } else {
        struct mmnode *current = mm->head;
        struct mmnode *last = mm->head;

        while (current != NULL) {
            printf("%s%p <- %p -> %p (base=%p, last=%p, size=%u)\n", current->type == NodeType_Allocated ? "       *" : "        ", current->prev, current, current->next, current->base, current->base + current->size - 1, current->size);
            if (current->next == NULL)
                last = current;
            current = current->next;
        }
    }
}

void mm_print_state(struct mm *mm) {
    print_mmnodes(mm);
}

errval_t mm_init(struct mm *mm, enum objtype objtype,
                     slab_refill_func_t slab_refill_func,
                     slot_alloc_t slot_alloc_func,
                     slot_refill_t slot_refill_func,
                     void *slot_alloc_inst)
{
    mm->slot_alloc = slot_alloc_func;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc_inst = slot_alloc_inst;
    mm->head = NULL;
    mm->objtype = objtype;

    size_t blocksize = sizeof(struct mmnode);
    slab_init(&mm->slabs, blocksize, &slab_default_refill);
    mm->slabs.refill_func = slab_refill_func;

    // TODO not sure about those
    //mm->stats_bytes_max = ;
    //mm->stats_bytes_available =;

    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm)
{
    assert(!"NYI");
}

static bool mmnode_overlap(struct mmnode *n1, struct mmnode *n2)
{
    genpaddr_t base1 = n1->base;
    genpaddr_t last1 = n1->base + n1->size - 1;
    genpaddr_t base2 = n2->base;
    genpaddr_t last2 = n2->base + n2->size - 1;

    return base1 <= last2 && base2 <= last1;
}

errval_t mm_add(struct mm *mm, struct capref cap, genpaddr_t base, size_t size)
{
    assert(mm != NULL);
    assert(size > 0);

    struct capinfo new_capinfo = {
        .cap = cap,
        .base = base,
        .size = size,
    };

    struct mmnode *new_node = (struct mmnode *) slab_alloc(&mm->slabs);

    if (new_node == NULL)
        return LIB_ERR_SLAB_ALLOC_FAIL;

    new_node->type = NodeType_Free;
    new_node->cap = new_capinfo;
    new_node->base = base;
    new_node->size = size;

    if (mm->head == NULL) {
        new_node->next = NULL;
        new_node->prev = NULL;
        mm->head = new_node;
    } else {
        struct mmnode *current = mm->head;
        if (mmnode_overlap(new_node, current))
            goto ERROR_OVERLAP;

        while (new_node->base > current->base && current->next != NULL) {
            current = current->next;
            if (mmnode_overlap(new_node, current))
                goto ERROR_OVERLAP;
        }

        if (new_node->base > current->base) {
            assert(current->next == NULL);
            // Insert new_node after current, as new last element
            new_node->next = NULL;
            new_node->prev = current;
            current->next = new_node;
        } else {
            // Insert new_node in front of current node
            new_node->next = current;
            new_node->prev = current->prev;
            if (current->prev != NULL)
                current->prev->next = new_node;
            else
                mm->head = new_node;
            current->prev = new_node;
        }
    }

    return SYS_ERR_OK;

ERROR_OVERLAP:
    slab_free(&mm->slabs, new_node);
    return MM_ERR_ALREADY_PRESENT;
}

static errval_t split_mmnode(struct mm *mm, struct mmnode *n, size_t size, size_t padding_start, struct mmnode **result_node)
{
    assert(n != NULL);
    assert(n->size >= size);

    // TODO Operate on static nodes here and copy them into slab allocated nodes after the retype.

    // Allocate new nodes
    struct mmnode *node_padding = NULL;
    if (padding_start > 0) {
        node_padding = (struct mmnode *) slab_alloc(&mm->slabs);
        if (node_padding == NULL)
            return LIB_ERR_SLAB_ALLOC_FAIL;

        node_padding->type = NodeType_Free;
        node_padding->cap = n->cap;
        node_padding->base = n->base;
        node_padding->size = padding_start;
    }

    struct mmnode *node_sized = (struct mmnode *) slab_alloc(&mm->slabs);
    if (node_sized == NULL) {
        slab_free(&mm->slabs, node_padding);
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    node_sized->type = NodeType_Allocated;
    node_sized->cap = n->cap;
    node_sized->base = n->base + padding_start;
    node_sized->size = size;

    struct mmnode *node_remaining = NULL;
    size_t size_remaining = n->size - padding_start - size;
    if (size_remaining > 0) {
        node_remaining = (struct mmnode *) slab_alloc(&mm->slabs);
        if (node_remaining == NULL) {
            slab_free(&mm->slabs, node_padding);
            slab_free(&mm->slabs, node_sized);
            return LIB_ERR_SLAB_ALLOC_FAIL;
        }

        node_remaining->type = NodeType_Free;
        node_remaining->cap = n->cap;
        node_remaining->base = n->base + padding_start + size;
        node_remaining->size = size_remaining;
    }

    // Set next and prev of all new nodes and neighboring nodes
    if (node_padding == NULL) {
        node_sized->prev = n->prev;
        if (n->prev != NULL)
            n->prev->next = node_sized;
        else
            mm->head = node_sized;
    } else {
        node_padding->prev = n->prev;
        node_padding->next = node_sized;
        node_sized->prev = node_padding;
        if (n->prev != NULL)
            n->prev->next = node_padding;
        else
            // TODO This case is currently untested
            mm->head = node_padding;
    }
    if (node_remaining == NULL) {
        node_sized->next = n->next;
        if (n->next != NULL)
            n->next->prev = node_sized;
    } else {
        node_sized->next = node_remaining;
        node_remaining->prev = node_sized;
        node_remaining->next = n->next;
        if (n->next != NULL)
            n->next->prev = node_remaining;
    }

    slab_free(&mm->slabs, n);

    *result_node = node_sized;
    return SYS_ERR_OK;
}

errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap)
{
    errval_t err;

    err = slab_ensure_margin(&mm->slabs, 6);
    if (err_is_fail(err))
        return err;

    // TODO Maybe look for smallest memory region that can be used?
    struct mmnode *current = mm->head;
    while (current != NULL) {
        // Find a free memory region that can accommodate the desired size including the required padding to conform to the specified alignment
        size_t remainder = current->base % alignment;
        size_t padding_start = 0;
        if (remainder != 0)
            padding_start = alignment - remainder;

        size_t size_aligned = size + padding_start;

        if (current->type == NodeType_Free && current->size >= size_aligned) {

            struct mmnode *new_node = NULL;
            err = split_mmnode(mm, current, size, padding_start, &new_node);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to split mmnode");
                return err_push(err, MM_ERR_SPLIT_NODE);
            }

            mm->slot_refill(mm->slot_alloc_inst);
            err = mm->slot_alloc(mm->slot_alloc_inst, 1, retcap);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to allocate new slot");
                return err_push(err, LIB_ERR_SLOT_ALLOC);
            }

            gensize_t offset = new_node->base - new_node->cap.base;
            assert(offset % BASE_PAGE_SIZE == 0);
            err = cap_retype(*retcap, new_node->cap.cap, offset, mm->objtype, new_node->size, 1);
            if (err_is_fail(err)) {
                // TODO Currently this leads to an inconsistent state, because the mmnode has already been split.
                DEBUG_ERR(err, "failed to retype capability");
                debug_printf("cap.base=%p, cap.size=%u, node.base=%p, node.size=%u, offset=%u, padding_start=%u\n", new_node->cap.base, new_node->cap.size, new_node->base, new_node->size, offset, padding_start);
                return err_push(err, LIB_ERR_CAP_RETYPE);
            }
            return SYS_ERR_OK;
        }
        current = current->next;
    }

    return MM_ERR_OUT_OF_MEMORY;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}

errval_t mm_free(struct mm *mm, struct capref cap, genpaddr_t base, gensize_t size)
{
    errval_t err;

    err = slab_ensure_margin(&mm->slabs, 6);
    if (err_is_fail(err))
        return err;

    struct mmnode *node_middle = NULL;
    struct mmnode *node_before;
    struct mmnode *node_after;
    struct mmnode *current = mm->head;

    while (current != NULL) {
        if (current->base == base && current->size == size) {
            node_middle = current;
            break;
        }
        current = current->next;
    }

    if (node_middle == NULL)
        return MM_ERR_NOT_FOUND;

    node_before = node_middle->prev;
    node_after = node_middle->next;

    // cap_delete is used instead of cap_destroy, because cap_destroy doesn't free the slot.
    err = cap_delete(cap);
    if (err_is_fail(err))
        return err_push(err, LIB_ERR_CAP_DELETE);

    // Free the slot. Remove this as soon as cap_destroy works.
    err = slot_free(cap);
    if (err_is_fail(err))
        return err_push(err, LIB_ERR_SLOT_FREE);

    struct mmnode *node_merged = (struct mmnode *) slab_alloc(&mm->slabs);
    if (node_merged == NULL)
        // TODO Currently this leads to an inconsistent state, because the capability has already been deleted.
        return LIB_ERR_SLAB_ALLOC_FAIL;

    node_merged->type = NodeType_Free;
    node_merged->cap = node_middle->cap;
    node_merged->size = node_middle->size;
    if (node_before == NULL)
        // TODO This case is currently untested
        // Middle node was the head, so the merged node should be the new head
        mm->head = node_merged;

    // Merge mmnode with other free mmnodes in before or after it, but only if they have the same original capability (i.e. they belong to the same memory region that was added with mm_add).
    if (node_before != NULL && node_before->type == NodeType_Free && node_before->cap.base == node_middle->cap.base) {

        // Merge with the node before
        node_merged->base = node_before->base;
        node_merged->size += node_before->size;
        node_merged->prev = node_before->prev;
        if (node_before->prev != NULL)
            node_before->prev->next = node_merged;
        else
            // TODO This case is currently untested
            // The merged node merged with the head, so the merged node should be the new head
            mm->head = node_merged;

        slab_free(&mm->slabs, node_before);
    } else {
        node_merged->base = node_middle->base;
        node_merged->prev = node_before;
        if (node_before != NULL)
            node_before->next = node_merged;
    }

    if (node_after != NULL && node_after->type == NodeType_Free && node_after->cap.base == node_middle->cap.base) {
        // Merge with the node after
        node_merged->next = node_after->next;
        node_merged->size += node_after->size;
        if (node_after->next != NULL)
            node_after->next->prev = node_merged;

        slab_free(&mm->slabs, node_after);
    } else {
        node_merged->next = node_after;
        if (node_after != NULL)
            node_after->prev = node_merged;
    }

    slab_free(&mm->slabs, node_middle);

    return SYS_ERR_OK;

}
