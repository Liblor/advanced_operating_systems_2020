/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>


static char slab_buf[64*sizeof(struct mmnode)];
static bool slab_buf_used;

static errval_t mm_slab_refill(struct slab_allocator *slabs) {
    // TODO real slab refill
    if (slab_buf_used) { return SYS_ERR_NOT_IMPLEMENTED; }
    slab_grow(slabs, slab_buf, sizeof(slab_buf));
    return SYS_ERR_OK;
}

static inline errval_t create_new_node(struct mm *mm,
                                       struct mmnode **new_node,
                                       genpaddr_t base,
                                       gensize_t size,
                                       enum nodetype type) {
    void *block = slab_alloc(&mm->slabs);
    if (block == NULL) { return LIB_ERR_SLAB_ALLOC_FAIL; }
    *new_node = (struct mmnode *)block;
    (*new_node)->type = type;
    (*new_node)->cap = (struct capinfo) {.base = base, .size = size};
    (*new_node)->base = base;
    (*new_node)->size = size;
    return SYS_ERR_OK;
}

static inline void insert_before(struct mm *mm, struct mmnode *new_node, struct mmnode *before) {
    new_node->prev = before->prev;
    if (new_node->prev != NULL) {
        new_node->prev->next = new_node;
    } else {
        assert(mm->head == before);
        mm->head = new_node;
    }
    new_node->next = before;
    before->prev = new_node;
}

// todo refactor
static void remove_node(struct mm *mm, struct mmnode *node) {
    if (node->prev != NULL) {
        node->prev->next = node->next;
    } else {
        assert(mm->head == node);
        mm->head = node->next;
    }
    if (node->next != NULL) {
        node->next->prev = node->prev;
    } else {
        assert(mm->tail == node);
        mm->tail = node->prev;
    }
    node->prev = node->next = NULL;
}

/**
 * @param node The queried  node
 * @param size How much space one wants to allocate
 * @return True iff enough space is available to allocate at this node
 */
static inline bool is_allocatable(struct mmnode *node, gensize_t size) {
    return node->size >= size && node->type == NodeType_Free;
}

static inline bool is_allocated_node(struct mmnode *node, genpaddr_t base, gensize_t size) {
    return node->base == base && node->size == size && node->type == NodeType_Allocated;
}

//////////////////////////////////////////////////////////////////////////////

errval_t mm_init(struct mm *mm, enum objtype objtype,
                     slab_refill_func_t slab_refill_func,
                     slot_alloc_t slot_alloc_func,
                     slot_refill_t slot_refill_func,
                     void *slot_alloc_inst) {
    // TODO: refactor to double linked circle
    if (slab_refill_func == NULL) {
        slab_refill_func = mm_slab_refill;
    }

    mm->slot_alloc = slot_alloc_func;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc_inst = slot_alloc_inst;
    mm->objtype = objtype;

    slab_init(&(mm->slabs), sizeof(struct mmnode), slab_refill_func);

    slab_buf_used = 0;

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
    debug_printf("[mm_add] base: %lu, size %lu\n", base, size);
    assert(mm->slabs.blocksize >= sizeof(struct mmnode));
    void *block = slab_alloc(&mm->slabs);
    if (block == NULL) {
        debug_printf("[mm_add] slab_alloc returned NULL\n");
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    struct mmnode *node = (struct mmnode *)block;
    node->type = NodeType_Free;
    node->cap = (struct capinfo) {.cap = cap, .base = base, .size = size};
    node->cap.parent = &node->cap.cap;
    node->base = base;
    node->size = size;

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
    if ((alignment % BASE_PAGE_SIZE) || alignment == 0) {
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
    errval_t err = create_new_node(mm, &new_node, curr->base, size, NodeType_Allocated);
    if (err_is_fail(err)) { return err; }
    new_node->cap.base = curr->cap.base;
    new_node->cap.size = curr->cap.size;
    new_node->cap.parent = curr->cap.parent;

    // Update current
    curr->base += size;
    curr->size -= size;

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
    err = cap_retype(new_node->cap.cap, *curr->cap.parent, new_node->base,
                     mm->objtype, size, 1);
    if (err_is_fail(err)) { return err_push(err, AOS_ERR_SLOT_REFILL_FAIL); }

    insert_before(mm, new_node, curr);

    return SYS_ERR_OK;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap) {
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}


errval_t mm_free(struct mm *mm, struct capref cap, genpaddr_t base, gensize_t size) {
    // XXX: What about partial free?
    if (size % BASE_PAGE_SIZE) {
        size += (BASE_PAGE_SIZE - size % BASE_PAGE_SIZE);
    }

    struct mmnode *curr = mm->head;
    while (curr != NULL && !is_allocated_node(curr, base, size)) {
        curr = curr->next;
    }
    if (curr == NULL) { return MM_ERR_NOT_FOUND; }

    errval_t err = cap_revoke(cap);
    if (err_is_fail(err)) { return err_push(err, MM_ERR_MM_FREE); }
    err = cap_destroy(cap);
    if (err_is_fail(err)) { return err_push(err, MM_ERR_MM_FREE); }
    curr->type = NodeType_Free;

    // TODO refactor
    struct mmnode *to_delete;
    if (curr->prev != NULL && curr->prev->type == NodeType_Free && curr->cap.base == curr->prev->cap.base) {
        assert(curr->cap.size == curr->prev->cap.size);
        assert(curr->prev->base + curr->prev->size == curr->base);
        curr->base = curr->prev->base;
        curr->size += curr->prev->size;

        to_delete = curr->prev;
        remove_node(mm, to_delete);
        slab_free(&mm->slabs, to_delete);
    }

    if (curr->next != NULL && curr->next->type == NodeType_Free && curr->cap.base == curr->next->cap.base) {
        assert(curr->cap.size == curr->next->cap.size);
        assert(curr->base + curr->size == curr->next->base);
        curr = curr->next;
        curr->base = curr->prev->base;
        curr->size += curr->prev->size;

        to_delete = curr->prev;
        remove_node(mm, to_delete);
        slab_free(&mm->slabs, to_delete);
    }

    return SYS_ERR_OK;
}
