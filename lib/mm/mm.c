/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>


/** slab refill function for slab allocator managed by mm.c */
static inline
errval_t mm_slab_refill_func(struct slab_allocator *slabs) {
    DEBUG_BEGIN;
    DEBUG_END;
    return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * Init memory manager
 * @param instance
 * @param objtype what kind of capability mm allocates
 * @param slab_refill_func slab provides mapped memory (think malloc),
 *        needs to be refilled periodically not to run out of mem (see mm#slab_allocator)
 *
 * @param slot_alloc_func alloc slots in a capability (slot_alloc_prealloc)
 * @param slot_refill_func function to create new cnode (l2c)
 *        if no more slots available for new capabilities
 * @param slot_alloc_inst instance to slot allocator
 *
 *
 * err = mm_init(&aos_mm, ObjType_RAM, NULL,
 *                  slot_alloc_prealloc, slot_prealloc_refill,
 *                  &init_slot_alloc);
 *
 * @return
 */
errval_t mm_init(struct mm *mm, enum objtype objtype,
                 slab_refill_func_t slab_refill_func,
                 slot_alloc_t slot_alloc_func,
                 slot_refill_t slot_refill_func,
                 void *slot_alloc_inst) {
    DEBUG_BEGIN;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc_inst = slot_alloc_inst;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc = slot_alloc_func;
    mm->objtype = objtype;

    if (slab_refill_func == NULL) {
        slab_refill_func = mm_slab_refill_func;
    }
    uint64_t blocksize = sizeof(struct mmnode);
    DEBUG_PRINTF("set blocksize for slab in mm %d bytes\n")

    slab_init(&mm->slabs, blocksize, slab_refill_func);
    mm->slabs.refill_func = slab_refill_func;

    DEBUG_END;
    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm) {
    DEBUG_BEGIN;
    assert(!"NYI");
    DEBUG_END;
}


/**
 * create a mmnode
 * @param mm this instance
 * @param cap capability
 * @param type type
 * @param base base addr of cap
 * @param size size of cap
 * @param offset offset of cap
 * @param res mmnode to return
 *
 *
 * @return errval err code
 */
static inline
errval_t create_mmnode(struct mm *mm,
                       struct capref cap, enum nodetype type, genpaddr_t base, size_t size, genpaddr_t offset,
                       struct mmnode **res) {
    assert(sizeof(struct mmnode) >= mm->slabs.blocksize);

    // TODO-BEAN: implement slab_refill function

    struct mmnode *node = *res;
    node = slab_alloc(&mm->slabs);

    if (node == NULL) {
        DEBUG_PRINTF("failed to alloc a new slab block. no memory from slab\n");
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    node->type = type;
    node->size = size;
    node->base = base;
    node->offset = offset;
    node->cap = (struct capinfo) {
            .cap = cap,
            .size = size,
            .base = base
    };
    return SYS_ERR_OK;
}

/**
 * Add memory capabilities to mm (assume: cap not already added)
 *
 * @param mm this ref
 * @param cap capability to the ram region
 * @param base base address of the ram region
 * @param size size of the ram region
 *
 * @return
 */
errval_t mm_add(struct mm *mm, struct capref cap, genpaddr_t base, size_t size) {
    DEBUG_BEGIN;
    // TODO-BEAN: handle failure ALREADY_PRESENT

    errval_t err;
    struct mmnode *node = NULL;
    err = create_mmnode(mm, cap, NodeType_Free, base, size, 0, &node);

    if (err_is_fail(err)) { return err_push(err, MM_ERR_MM_ADD); }

    if (mm->head == NULL) {
        assert(mm->tail == NULL);
        mm->head = node;
        mm->tail = node;
    } else {
        struct mmnode *last = mm->tail;
        last->next = node;
        node->prev = last;
    }
    DEBUG_PRINTF("adding RAM region (%p/%zu)\n", base, size);
    DEBUG_END;
    return SYS_ERR_OK;
}


/** does current node fulfill requirement to be picked as suitable free node */
static inline
bool is_node_suitable_alloc(struct mmnode *node, size_t size) {
    return node->size >= size && node->type == NodeType_Free;
}

/** Enqueue node behind other in linked list of mmnode
 *  other->prev <-> other <-> new_node <-> other->next */
static inline
void enqueue_node_behind_other(struct mm *mm, struct mmnode *new_node, struct mmnode *other) {
    if (other == mm->tail) {
        mm->tail = new_node;
    }

    new_node->next = other->next;
    if (other->next != NULL) {
        other->next->prev = new_node;
    }
    new_node->prev = other;
    other->next = new_node;

    assert(other->next == new_node);
    assert(new_node->prev = other);
}


static inline
size_t alloc_align_size(size_t size) {
    return size + BASE_PAGE_SIZE - (size % BASE_PAGE_SIZE); // align size to page size
}
/**
 * Request aligned ram capability
 *
 * @param mm this instance
 * @param size size of capability to request
 * @param alignment alignment of address
 * @param retcap cap to return
 * @return
 */
errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap) {
    DEBUG_BEGIN;
    errval_t err;
    // TODO-BEAN: how to handle alignment?

    if (alignment == 0 || alignment % BASE_PAGE_SIZE != 0) { return LIB_ERR_ALIGNMENT; }
    size = alloc_align_size(size);

    struct mmnode *node = mm->head;
    while (node != NULL && !is_node_suitable_alloc(node, size)) { node = node->next; }
    if (node == NULL) { return MM_ERR_NOT_ENOUGH_RAM; }

    /* In order to mm_alloc memory we need;
     * - a free slot for new cnode
     * - split existing ram capability in appropriate size (retype)
     *   We use the tail for the new memory to allocate and create a new mmnode
     *   based on the tail which is enqueue after the existing mmnode (head).
     */
    err = mm->slot_alloc(mm->slot_alloc_inst, 1, retcap);
    if (err_is_fail(err)) { return err_push(err, MM_ERR_SLOT_MM_ALLOC); }
    mm->slot_refill(mm->slot_alloc_inst);
    if (err_is_fail(err)) { return err_push(err, MM_ERR_SLOT_NOSLOTS); }


    /* upon retype the head and tail mmnode keep the same base.
     * The tail mmnode updates its offset and size.
     */
    gensize_t new_node_offset = size;
    err = cap_retype(*retcap, node->cap.cap, new_node_offset, mm->objtype, size, 1);
    if (err_is_fail(err)) { err_push(err, MM_ERR_MISSING_CAPS); }

    // modify head (stays NodeType_Free)
    assert(node->type == NodeType_Free);
    node->size -= size;
    node->cap.size -= size;

    // create new mmnode (becomes NodeType_Allocated)
    struct mmnode *new_node = NULL;
    err = create_mmnode(mm, *retcap, NodeType_Allocated, node->base, size, new_node_offset, &new_node);
    if (err_is_fail(err)) { return err_push(err, MM_ERR_MM_ALLOC); }


    enqueue_node_behind_other(mm, new_node, node);
    assert(node->next == new_node);
    assert(new_node->prev = node);

    DEBUG_END;
    return SYS_ERR_OK;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap) {
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}

errval_t mm_free(struct mm *mm, struct capref cap, genpaddr_t base, gensize_t size) {
    DEBUG_BEGIN;
    errval_t err;
    size = alloc_align_size(size);

    err = cap_revoke(cap);
    if (err_is_fail(err)) {return err_push(err, MM_ERR_MM_FREE);}


    // TODO-BEAN: partial free? base addr is not base addr from capability?, fragmentaion?

    DEBUG_END;
    return SYS_ERR_OK;
}