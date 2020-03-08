/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>


static errval_t mm_slab_refill(void *slabs) {
    return LIB_ERR_NOT_IMPLEMENTED;
}

//////////////////////////////////////////////////////////////////////////////

errval_t mm_init(struct mm *mm, enum objtype objtype,
                     slab_refill_func_t slab_refill_func,
                     slot_alloc_t slot_alloc_func,
                     slot_refill_t slot_refill_func,
                     void *slot_alloc_inst) {
    if (slab_refill_func == NULL) {
        slot_refill_func = &mm_slab_refill;
    }

    mm->slot_alloc = slot_alloc_func;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc_inst = slot_alloc_inst;
    mm->objtype = objtype;

    slab_init(&mm->slabs, sizeof(struct mmnode), slab_refill_func);

    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm) {
    assert(!"NYI");
}

errval_t mm_add(struct mm *mm, struct capref cap, genpaddr_t base, size_t size) {
    debug_printf("[mm_add] base: %i, size &i\n", base, size);
    assert(mm->slabs.blocksize >= sizeof(struct mmnode));
    void *block = slab_alloc(&mm->slabs);
    if (block == NULL) {
        debug_printf("[mm_add] slab_alloc returned NULL\n");
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    struct mmnode *node = (struct mmnode *)block;
    node->type = NodeType_Free;
    node->cap = (struct capinfo) {.cap = cap, .base = base, .size = size};
    base = base;
    size = size;

    // add_node
    if (mm->head == NULL) {
        assert(mm->tail == NULL);
        mm->head = mm->tail = node;
    } else {
        mm->tail->next = node;
        node->prev = mm->tail;
        mm->tail = node;
    }

    return SYS_ERR_OK;
}

errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap) {
    if (alignment % BASE_PAGE_SIZE) {
        debug_printf("[mm_alloc_aligned] Misaligned memory\n");
        return AOS_ERR_MM_MISALIGN;
    }

    if (size % BASE_PAGE_SIZE) {
        debug_printf("[mm_alloc_aligned] adjust size\n");
        size = size + (BASE_PAGE_SIZE - size % BASE_PAGE_SIZE);
    }


    return LIB_ERR_NOT_IMPLEMENTED;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap) {
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}


errval_t mm_free(struct mm *mm, struct capref cap, genpaddr_t base, gensize_t size) {
    return LIB_ERR_NOT_IMPLEMENTED;
}
