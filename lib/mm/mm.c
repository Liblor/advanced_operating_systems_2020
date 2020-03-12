/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>

#define SLAB_REFILL_THRESHOLD 12
#define ENABLE_DUMP 0

#define mm_err_is_fail(err)  \
(err_is_fail(err) ? (DEBUG_ERR(err, "failure in mm.c "), true) : false)

static inline
void dump_capref(struct capref *, const char *);

/** slab refill function for slab allocator managed by mm.c */
static inline
errval_t mm_slab_refill_func(struct slab_allocator *slabs) {
    DEBUG_BEGIN;
    DEBUG_END;
    return slab_default_refill(slabs);
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
    mm->slot_alloc_inst = slot_alloc_inst; // TODO deref and set mm instance
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc = slot_alloc_func;
    mm->objtype = objtype;
    mm->slab_is_refilling = false;

    slab_refill_func = mm_slab_refill_func;

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

static inline
errval_t ensure_slabs_refilled(struct mm *mm) {
    errval_t err;
    DEBUG_PRINTF("slabs free: %zu, slabs total: %zu\n", mm->slabs.slabs->free, mm->slabs.slabs->total);

    if (mm->slabs.slabs->free < SLAB_REFILL_THRESHOLD
        && !mm->slab_is_refilling) {
        DEBUG_PRINTF("entering slab refilling mode, slabs free: %zu, slabs total: %zu\n",
                mm->slabs.slabs->free, mm->slabs.slabs->total);
        mm->slab_is_refilling = true;
        err = mm->slabs.refill_func(&mm->slabs);
        if (mm_err_is_fail(err)) {
            DEBUG_ERR(err, "cannot create more slab in mm_alloc. slab refilling state = 1");
            return err_push(err, MM_ERR_MM_SLAB_REFILL);
        }
        mm->slab_is_refilling = false;
    }
    return SYS_ERR_OK;
}

static inline
errval_t create_node_without_capinfo(struct mm *mm,
        enum nodetype type, genpaddr_t base, size_t size, struct mmnode **res) {

    assert(sizeof(struct mmnode) >= mm->slabs.blocksize);
    *res = (struct mmnode *) slab_alloc(&mm->slabs);
    struct mmnode *node = *res;
    if (node == NULL) {
        DEBUG_PRINTF("failed to alloc a new slab block. no memory from slab\n");
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    node->type = type;
    node->size = size;
    node->base = base;
    node->next = NULL;
    node->prev = NULL;
    node->capinfo = (struct capinfo) {
            .cap_origin_unmapped = NULL,
            .base = 0,
            .size = 0,
            .cap = {},
    };
    return SYS_ERR_OK;
}

// we assume that base is alsways aligned to basepage size
// we assume that no ram caps are added that are already present
errval_t mm_add(struct mm *mm, struct capref cap, genpaddr_t base, size_t size) {
    DEBUG_BEGIN;
    errval_t err;
    err = ensure_slabs_refilled(mm);
    if (mm_err_is_fail(err)) {
        return err;
    }
    struct mmnode *node = NULL;
    err = create_node_without_capinfo(mm, NodeType_Free, base, size, &node);
    if (mm_err_is_fail(err)) { return err_push(err, MM_ERR_MM_ADD); }
    node->capinfo = (struct capinfo) {
            .cap = cap,
            .size = size,
            .base = base,
            .cap_origin_unmapped = &(node->capinfo), // mm node of unsplit RAM cap refers to its own capinfo

    };
    assert(node->capinfo.cap_origin_unmapped == &node->capinfo);
    assert(node->base == node->capinfo.base);
    assert(node->size == node->capinfo.size);

    if (mm->head == NULL) {
        assert(mm->tail == NULL);
        mm->head = node;
        mm->tail = node;
    } else {
        struct mmnode *last = mm->tail;
        last->next = node;
        node->prev = last;
    }
    DEBUG_PRINTF("adding RAM region (base: %p/ size: %zu MB)\n", base, (size / 1024 / 1024));
    mm_dump_mmnode(node, NULL);
    DEBUG_END;
    return SYS_ERR_OK;
}


/** does current node fulfill requirement to be picked as suitable free node */
static inline
bool is_node_suitable_alloc(struct mmnode *node, size_t size) {
    return node->size >= size && node->type == NodeType_Free;
}

/** Enqueue node behind other in linked list of mmnode
 *  from;
 *  other->prev <-> other <-> other->next
 *  to;
 *  other->prev <-> new_node <-> other <-> other->next */
static inline
void enqueue_node_before_other(struct mm *mm, struct mmnode *new_node, struct mmnode *other) {
    DEBUG_BEGIN;
    struct mmnode *_old_prev = other->prev;
    struct mmnode *_old_next = other->next;

    if (other == mm->head) {
        mm->head = new_node;
    }
    new_node->next = other;
    if (other->prev != NULL) {
        other->prev->next = new_node;
    }
    new_node->prev = other->prev;
    other->prev = new_node;

    assert(other->prev == new_node);
    assert(new_node->next == other);
    assert(new_node->prev == _old_prev);
    assert(other->next == _old_next);
    DEBUG_END;
}

static inline
size_t alloc_align_size(size_t size) {
    size_t new_size = ROUND_UP(size, BASE_PAGE_SIZE);
    return new_size;
}

static inline
errval_t get_slot_for_cap(struct mm *mm, struct capref *retcap) {
    errval_t err;
    err = mm->slot_alloc(mm->slot_alloc_inst, 1, retcap);
    if (mm_err_is_fail(err)) {
        return err_push(err, MM_ERR_SLOT_MM_ALLOC);
    }
    mm->slot_refill(mm->slot_alloc_inst);
    if (mm_err_is_fail(err)) {
        return err_push(err, MM_ERR_SLOT_NOSLOTS);
    }
    return SYS_ERR_OK;
}

// Alignment is currently not implemented, and can be passed as a recommendation.
// only guarantee is that allocated ram caps are always aligned to base page size.
errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap) {
    DEBUG_BEGIN;
    errval_t err;
    if (alignment == 0 || alignment % BASE_PAGE_SIZE != 0) { return LIB_ERR_ALIGNMENT; }

    size = alloc_align_size(size);
    err = ensure_slabs_refilled(mm);
    if (mm_err_is_fail(err)) {
        return err;
    }

    // find node in pool of free nodes
    struct mmnode *node = mm->head;
    while (node != NULL && !is_node_suitable_alloc(node, size)) { node = node->next; }
    if (node == NULL) { return MM_ERR_NOT_ENOUGH_RAM; }

    // create a slot for returning cap
    err = get_slot_for_cap(mm, retcap);
    if (mm_err_is_fail(err)) { goto free_slot_and_return_err; }

    /*
     * How to split memory from existing (free) node
     * |-------|    |-|-----|
     * |  A    | -> |B|  A  |
     * |-------|    |-|-----|
     *
     * A: original node (node)
     * B: new node with requested size (return) (new_node)
     * B is enqueued before A and A is updated
     */
    const gensize_t offset_into_origin = node->base - node->capinfo.base;
    DEBUG_PRINTF("retyping cap (%p) from source cap (%p) with offset %zu and size %zu\n",
                 retcap, &node->capinfo.cap_origin_unmapped->cap,
                 offset_into_origin,
                 size);

    err = cap_retype(*retcap, node->capinfo.cap_origin_unmapped->cap, offset_into_origin, mm->objtype, size, 1);
    if (mm_err_is_fail(err)) {
        err = err_push(err, MM_ERR_MM_ALLOC_RETYPE);
        goto free_slot_and_return_err;
    }

    // create new node (becomes NodeType_Allocated)
    struct mmnode *new_node = NULL;
    err = create_node_without_capinfo(mm, NodeType_Allocated, node->base, size, &new_node);
    if (mm_err_is_fail(err)) {
        err = err_push(err, MM_ERR_MM_ALLOC);
        goto free_slot_and_return_err;
    }
    new_node->capinfo = (struct capinfo) {
            .cap_origin_unmapped = &node->capinfo,
            .cap = *retcap,
            .base = node->capinfo.base,
            .size = node->capinfo.size
    };

    // shrink existing node (stays NodeType_free)
    assert(node->type == NodeType_Free);
    node->type = NodeType_Free;
    node->base = node->base + size;
    node->size = node->size - size;
    enqueue_node_before_other(mm, new_node, node);

    mm_dump_mmnode(node, "updated free node");
    mm_dump_mmnode(new_node, "new allocated node");

    DEBUG_END;
    return SYS_ERR_OK;

    /*
     * clean up on error
     */
    free_slot_and_return_err:
    slot_free(*retcap); // dont capture error of free
    return err;

}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap) {
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}

/**
 * can merge `node` with free `other` for delete of `node`
 */
static inline
bool can_merge_node(struct mmnode *node, struct mmnode *other) {
    return other != NULL && other->type == NodeType_Free
           && node->capinfo.base == other->capinfo.base;
}

static inline
void free_and_merge_node_with_next(struct mm *mm, struct mmnode *current) {
    DEBUG_PRINTF("node has origin to the right/ next which is NodeType_Free\n");
    mm_dump_mmnode(current, "node to free");
    mm_dump_mmnode(current->next, "origin");
    /*
     * |-|-----|    |-------| A is free
     * |B|  A  | -> |   A   |
     * |-|-----|    |-------|
     * where B is current, A is current->next, and A is origin of B
     */
    struct mmnode *origin = current->next;
    const gensize_t _old_size = origin->size;

    origin->size += current->size;
    origin->base = current->base;
    origin->prev = current->prev;
    if (current->prev != NULL) { current->prev->next = origin; }
    if (current == mm->head) { mm->head = origin; }
    {
        assert(origin->type == NodeType_Free);
        assert(origin->size == _old_size + current->size);
        assert(origin->base == current->base);
        assert(origin->prev != current);
        if (origin->prev != NULL) {
            assert (origin->prev->next != current);
        }
    }
    slab_free(&mm->slabs, current);
    mm_dump_mmnode(origin, "origin after free");
}

static inline
void free_and_merge_node_with_prev(struct mm *mm, struct mmnode *current) {
    DEBUG_PRINTF("node has origin to the left which is free\n");
    mm_dump_mmnode(current, "node to free");
    mm_dump_mmnode(current->next, "origin");
    /*
     * |-----|-|    |-------| A is free
     * |  A  |B| -> |   A   |
     * |-----|-|    |-------|
     * where B is current, A is current->prev, and A is origin of B
     */
    struct mmnode *origin = current->prev;
    const genpaddr_t _old_base = origin->base;
    const gensize_t _old_size = origin->size;

    origin->size += current->size;
    // origin->base stays the same
    origin->next = current->next;
    if (current->next != NULL) { current->next->prev = origin; }
    if (current == mm->tail) { mm->tail = origin; }
    {
        assert(origin->type == NodeType_Free);
        assert(origin->size == _old_size + current->size);
        assert(origin->base == _old_base);
        assert(origin->next != current);
        if (origin->next != NULL) {
            assert (origin->next->prev != current);
        }
    }
    slab_free(&mm->slabs, current);
    mm_dump_mmnode(origin, "origin after free");
}

// TODO-BEAN: partial free?
errval_t mm_free(struct mm *mm, struct capref cap, genpaddr_t base, gensize_t size) {
    DEBUG_BEGIN;
    DEBUG_PRINTF("free of base %p and size %zu\n", base, size);
    errval_t err;

    size = alloc_align_size(size);
    struct mmnode *current = mm->head;
    while (current != NULL) {
        if (current->base == base && current->size == size) { break; }
        current = current->next;
    }
    if (current == NULL) {
        DEBUG_ERR(MM_ERR_MM_FREE_NOT_FOUND, "node not found");
        return MM_ERR_MM_FREE_NOT_FOUND;
    }
    assert(current->type == NodeType_Allocated);
    assert(current->base == base);
    assert(current->size == size);

    err = cap_delete(cap);
    if (mm_err_is_fail(err)) { return err_push(err, MM_ERR_MM_FREE_CAP_DEL); }
    err = slot_free(cap);
    if (mm_err_is_fail(err)) { return err_push(err, MM_ERR_MM_FREE); }

    if (current != mm->tail && can_merge_node(current, current->next)) {
        free_and_merge_node_with_next(mm, current);
    } else if (current != mm->head && can_merge_node(current, current->prev)) {
        free_and_merge_node_with_prev(mm, current);
    } else {
        /*
         * current node is in between two NodeType_Alloacted nodes
         * or they dont share the same origin
         */
        current->type = NodeType_Free;
        {
            DEBUG_PRINTF("node has no free origin to left or right\n");
            mm_dump_mmnode(current, "current");
            mm_dump_mmnode(current->next, "current->next");
            mm_dump_mmnode(current->prev, "current->prev");
        }
    }
    DEBUG_END;
    return SYS_ERR_OK;
}

// ---------------------------------------
// methods to dump/ trace objects
// ---------------------------------------
static inline
void dump_capinfo(struct capinfo *capinfo, const char *msg) {
    if (!ENABLE_DUMP) { return; }
    if (msg != NULL) {
        DEBUG_PRINTF("%s \n", msg);
    }
    DEBUG_PRINTF(">> capinfo: %p \n", capinfo);
    if (capinfo == NULL) { return; }
    DEBUG_PRINTF("\t\tbase: %p\n", capinfo->base);
    DEBUG_PRINTF("\t\tsize: %zu (%zu KB, %zu MB)\n",
                 capinfo->size, capinfo->size / 1024, capinfo->size / 1024 / 1024);
    DEBUG_PRINTF("\t\torigin: %p \n", capinfo->cap_origin_unmapped);
    DEBUG_PRINTF("\t\tcap: %p \n", &capinfo->cap);
    DEBUG_PRINTF("\t\tcap/slot: %zu \n", capinfo->cap.slot);
    DEBUG_PRINTF("\t\tcap/cnode: %p \n", &capinfo->cap.cnode);
}

void mm_dump_mmnode(struct mmnode *mmnode, const char *msg) {
    if (!ENABLE_DUMP) { return; }
    if (msg != NULL) {
        DEBUG_PRINTF("%s \n", msg);
    }
    DEBUG_PRINTF("-- mmnode: %p \n", mmnode);
    if (mmnode == NULL) { return; }
    DEBUG_PRINTF("\ttype: %d (0 is free)\n", mmnode->type);
    DEBUG_PRINTF("\tbase: %p\n", mmnode->base);
    DEBUG_PRINTF("\tsize: %zu (%zu KB , %zu MB)\n",
                 mmnode->size, mmnode->size / 1024, mmnode->size / 1024 / 1024);
    DEBUG_PRINTF("\tprev: %p\n", mmnode->prev);
    DEBUG_PRINTF("\tnext: %p\n", mmnode->next);
    dump_capinfo(&mmnode->capinfo, NULL);
}

void dump_capref(struct capref *capref, const char *msg) {
    if (!ENABLE_DUMP) { return; }
    if (msg != NULL) {
        DEBUG_PRINTF("%s \n", msg);
    }
    DEBUG_PRINTF("++ capref: %p \n", capref);
    if (capref == NULL) { return; }
    DEBUG_PRINTF("\tslot: %zu \n", capref->slot);
    DEBUG_PRINTF("\tcnode: %p \n", capref->cnode);
    DEBUG_PRINTF("\tcnode/croot: %p \n", capref->cnode.croot);
    DEBUG_PRINTF("\tcnode/cnode: %p \n", capref->cnode.cnode);
    DEBUG_PRINTF("\tcnode/level: %d \n", capref->cnode.level);
}

void mm_dump_mmnodes(struct mm *mm) {
    if (mm->head == NULL) return;
    struct mmnode *n = mm->head;
    do {
        mm_dump_mmnode(n, NULL);
        n = n->next;
    } while (n != NULL && n != mm->tail);
    assert(n == mm->tail);
}

