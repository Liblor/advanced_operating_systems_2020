/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>


static inline errval_t create_new_node(struct mm *mm,
                                       struct mmnode **new_node,
                                       genpaddr_t base,
                                       gensize_t size,
                                       enum nodetype type,
                                       struct capref *parent,
                                       genpaddr_t cap_base,
                                       gensize_t cap_size,
                                       struct capref *cap) {
    void *block = slab_alloc(&mm->slabs);
    if (block == NULL) { return LIB_ERR_SLAB_ALLOC_FAIL; }

    *new_node = (struct mmnode *)block;
    (*new_node)->type = type;
    (*new_node)->cap = (struct capinfo) {
        .base = cap_base,
        .size = cap_size,
        .parent = parent,
        .cap = *cap,
    };
    (*new_node)->base = base;
    (*new_node)->size = size;
    return SYS_ERR_OK;
}

static inline errval_t mm_slab_threshold_refill(struct mm *mm) {
    if (slab_freecount(&mm->slabs) <= SLAB_FREE_BLOCKS_THRESHOLD && !mm->slab_refilling) {
        mm->slab_refilling = true;
        errval_t err = mm->slabs.refill_func(&mm->slabs);
        mm->slab_refilling = false;
        if (err_is_fail(err)) { return err_push(err, LIB_ERR_SLAB_REFILL); }
    }
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

/**
 * Removes node from linked list. Does NOT free the memory of node
 * @param mm
 * @param node Node to remove
 */
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


static inline void merge_with_prev_node(struct mm *mm, struct mmnode *node) {
    assert(node->type == node->prev->type);
    assert(node->cap.size == node->prev->cap.size);
    assert(node->prev->base + node->prev->size == node->base);
    if (mm->head == node->prev) {
        mm->head = node;
    }
    node->base = node->prev->base;
    node->size += node->prev->size;

    struct mmnode *to_delete = node->prev;
    remove_node(mm, to_delete);
    slab_free(&mm->slabs, to_delete);
}

static inline errval_t alloc_node(struct mm *mm, struct mmnode *node) {
    // new slot
    struct capref cap;
    errval_t err = mm->slot_alloc(mm->slot_alloc_inst, 1, &cap);
    if (err_is_fail(err)) { return err_push(err, LIB_ERR_SLOT_ALLOC); }
    err = mm->slot_refill(mm->slot_alloc_inst);         // TODO: only refill when needed
    if (err_is_fail(err)) {
        err_push(err, AOS_ERR_SLOT_REFILL_FAIL);
        goto free_slot;
    }

    gensize_t offset = node->base - node->cap.base;
    err = cap_retype(cap, *(node->cap.parent), offset, mm->objtype, node->size, 1);
    if (err_is_fail(err)) {
        err_push(err, SYS_ERR_RETYPE_CREATE);
        goto free_slot;
    }

    node->cap.cap = cap;
    node->type = NodeType_Allocated;

    return SYS_ERR_OK;

free_slot:
    slot_free(cap);
    return err;
}

static inline errval_t split_off(struct mm *mm, struct mmnode *node, gensize_t size) {
    // create new node
    struct mmnode *new_node;
    errval_t err = create_new_node(mm, &new_node, node->base, size, node->type,
                          node->cap.parent, node->cap.base, node->cap.size, &node->cap.cap);
    if (err_is_fail(err)) { return err; }

    // Update node
    node->base += size;
    node->size -= size;

    insert_before(mm, new_node, node);

    return SYS_ERR_OK;
}

/**
 * @param node The queried  node
 * @param size How much space one wants to allocate
 * @param alignment Alignment of allocation
 * @return True iff enough space is available to allocate at this node with the provided alignment
 */
static inline bool is_allocatable(struct mmnode *node, gensize_t size, gensize_t alignment) {
    genpaddr_t aligned_base = ROUND_UP(node->base, alignment);
    bool no_underflow = aligned_base >= node->base;
    bool in_range = node->base + node->size > aligned_base;
    bool enough_space = node->size - (aligned_base - node->base) >= size;

    return node->type == NodeType_Free && no_underflow && in_range && enough_space;
}

static inline bool is_allocated_node(struct mmnode *node, genpaddr_t base, gensize_t size) {
    return node->base == base && node->size == size && node->type == NodeType_Allocated;
}

static inline bool is_mergeable(struct mmnode *prev, struct mmnode *next) {
    return prev != NULL && prev->next == next && prev->type == next->type && prev->cap.base == next->cap.base;
}

//////////////////////////////////////////////////////////////////////////////

errval_t mm_init(struct mm *mm, enum objtype objtype,
                     slab_refill_func_t slab_refill_func,
                     slot_alloc_t slot_alloc_func,
                     slot_refill_t slot_refill_func,
                     void *slot_alloc_inst) {
    // XXX: maybe refactor to double linked circle
    if (slab_refill_func == NULL) {
        slab_refill_func = slab_default_refill;
    }

    mm->slab_refilling = false;
    mm->slot_alloc = slot_alloc_func;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc_inst = slot_alloc_inst;
    mm->objtype = objtype;
    mm->head = NULL;
    mm->tail = NULL;

    struct slot_prealloc *spre = (struct slot_prealloc *) slot_alloc_inst;
    spre->mm = mm;

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
    assert(mm->slabs.blocksize >= sizeof(struct mmnode));
    debug_printf("[mm_add] base: %lu, size %lu\n", base, size);

    errval_t err = mm_slab_threshold_refill(mm);
    if (err_is_fail(err)) { return err; }

    struct mmnode *node;
    err = create_new_node(mm, &node, base, size, NodeType_Free, NULL, base, size, &cap);
    if (err_is_fail(err)) { return err; }
    node->cap.parent = &node->cap.cap;

    // append node
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
    debug_printf("[mm_alloc_aligned] alignment: %lu, size %lu\n", alignment, size);
    if ((alignment % BASE_PAGE_SIZE) || alignment == 0) { return AOS_ERR_MM_MISALIGN; }
    size = ROUND_UP(size, BASE_PAGE_SIZE);

    errval_t err = mm_slab_threshold_refill(mm);
    if (err_is_fail(err)) { return err; }

    // find node with enough memory
    struct mmnode *curr = mm->head;
    while (curr != NULL && !is_allocatable(curr, size, alignment)) { curr = curr->next; }
    if (curr == NULL) { return LIB_ERR_RAM_ALLOC_FIXED_EXHAUSTED; }

    genpaddr_t aligned_base = ROUND_UP(curr->base, alignment);       // overflow checked in is_allocatable

    if (aligned_base == curr->base) {
        err = split_off(mm, curr, size);
        if (err_is_fail(err)) { return err; }
    } else {
        // TODO: remove size 0 nodes if it isn't end of original ram cap
        gensize_t pad_size = (aligned_base - curr->base);
        err = split_off(mm, curr, pad_size);
        if (err_is_fail(err)) { return err; }
        err = split_off(mm, curr, size);
        if (err_is_fail(err)) { return err; }
    }
    struct mmnode *allocatable_node = curr->prev;
    alloc_node(mm, allocatable_node);
    *retcap = allocatable_node->cap.cap;

    return SYS_ERR_OK;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap) {
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}


errval_t mm_free(struct mm *mm, struct capref cap, genpaddr_t base, gensize_t size) {
    size = ROUND_UP(size, BASE_PAGE_SIZE);

    // find node to free
    struct mmnode *curr = mm->head;
    while (curr != NULL && !is_allocated_node(curr, base, size)) {
        curr = curr->next;
    }
    if (curr == NULL) { return MM_ERR_NOT_FOUND; }

    // XXX: cap_revoke not fully implemented
    // errval_t err = cap_revoke(cap);
    // if (err_is_fail(err)) { return err_push(err, MM_ERR_MM_FREE); }
    errval_t err = cap_destroy(cap);
    if (err_is_fail(err)) { return err_push(err, MM_ERR_MM_FREE); }
    curr->type = NodeType_Free;

    if (is_mergeable(curr->prev, curr)) {
        merge_with_prev_node(mm, curr);
    }
    if (is_mergeable(curr, curr->next)) {
        merge_with_prev_node(mm, curr->next);
    }

    return SYS_ERR_OK;
}
