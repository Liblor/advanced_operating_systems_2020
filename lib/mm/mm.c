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

static inline errval_t create_new_node(struct mm *mm,
                                       struct mmnode **new_node,
                                       genpaddr_t base,
                                       gensize_t size,
                                       gensize_t offset) {
    void *block = slab_alloc(&mm->slabs);
    if (block == NULL) { return LIB_ERR_SLAB_ALLOC_FAIL; }
    *new_node = (struct mmnode *)block;
    (*new_node)->type = NodeType_Allocated;
    (*new_node)->cap = (struct capinfo) {.base = base, .size = size};
    (*new_node)->base = base;
    (*new_node)->size = size;
    (*new_node)->offset = offset;
    return SYS_ERR_OK;
}

static inline void insert_before(struct mm *mm, struct mmnode *new_node, struct mmnode *before) {
    new_node->prev = before->prev;
    if (new_node->prev != NULL) {
        new_node->prev->next = new_node;
    }
    new_node->next = before;
    before->prev = new_node;
}

/**
 * @param node The queried  node
 * @param size How much space one wants to allocate
 * @return True iff enough space is available to allocate at this node
 */
static inline bool is_allocatable(struct mmnode *node, gensize_t size) {
    return node->size >= size && node->type == NodeType_Free;
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

    slab_init(&(mm->slabs), sizeof(struct mmnode), slab_refill_func);

    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm) {
    assert(!"NYI");
}

/**
 * Add capability to memory manager
 * Added capabilities (cap) must be distinct and non-overlapping, undefined behavior otherwise.
 *
 * @param mm Memory Manager
 * @param cap Distinct capabilities
 * @param base Base address
 * @param size Size of capability
 * @return Error
 */
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
        assert(mm->tail != NULL);
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
        size += (BASE_PAGE_SIZE - size % BASE_PAGE_SIZE);
    }

    // find node with enough memory
    struct mmnode *curr = mm->head;
    // TODO check alignment
    //      But handle case mentioned below first
    while (curr != NULL && !is_allocatable(curr, size)) { curr = curr->next; }
    if (curr == NULL) { return LIB_ERR_RAM_ALLOC_FIXED_EXHAUSTED; }

    // create new node
    struct mmnode *new_node;
    errval_t err = create_new_node(mm, &new_node, curr->base, size, curr->offset);
    if (err_is_fail(err)) { return err; }

    // Update current
    curr->size -= size;
    curr->offset += size;

    // new slot
    // TODO: only refill when needed
    err = mm->slot_alloc(mm->slot_alloc_inst, 1, &new_node->cap.cap);
    if (err_is_fail(err)) { return err_push(err, LIB_ERR_SLOT_ALLOC); }
    err = mm->slot_refill(mm->slot_alloc_inst);
    if (err_is_fail(err)) { return err_push(err, AOS_ERR_SLOT_REFILL_FAIL); }

    // TODO: handle case, where 1 page size is allocated (from left, page aligned)
    //       and then a page size 2page aligned space is allocated
    //       | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
    //         A   ?   A   A  <- make node from ?
    err = cap_retype(new_node->cap.cap, curr->cap.cap, new_node->offset,
                     mm->objtype, curr->offset, 1);
    if (err_is_fail(err)) { return err_push(err, AOS_ERR_SLOT_REFILL_FAIL); }

    insert_before(mm, new_node, curr);

    return SYS_ERR_OK;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap) {
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}


errval_t mm_free(struct mm *mm, struct capref cap, genpaddr_t base, gensize_t size) {
    // XXX: What about partial free?
    struct mmnode *curr = mm->head;

    return LIB_ERR_NOT_IMPLEMENTED;
}
