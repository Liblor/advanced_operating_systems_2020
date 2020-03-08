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
 * Add memory capabilities to mm
 * @param mm this ref
 * @param cap capability to the ram region
 * @param base base address of the ram region
 * @param size size of the ram region
 *
 * @return
 */
errval_t mm_add(struct mm *mm, struct capref cap, genpaddr_t base, size_t size) {
    // TODO-BEAN: failure ALREADY_PRESENT     "Node already present in add_node()",
    //            what if add is called with same cap twice
    DEBUG_BEGIN;
    assert(sizeof(struct mmnode) >= mm->slabs.blocksize);

    // TODO-BEAN: implement slab_refill function
    struct mmnode *node = slab_alloc(&mm->slabs);
    if (node == NULL) {
        DEBUG_PRINTF("mm_add failed to alloc a new slab block. no memory from slab\n");
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    node->type = NodeType_Free;
    node->size = size;
    node->base = base;
    node->cap = (struct capinfo) {
            .cap = cap,
            .size = size,
            .base = base
    };
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

    if (alignment % BASE_PAGE_SIZE != 0) {
        DEBUG_PRINTF("mm_alloc_align alignment does not match base page size\n");
        return LIB_ERR_ALIGNMENT;
    }
    if (mm->head == NULL) {
        DEBUG_PRINTF("mm_alloc_align has no initial ram. call add first()\n");
        return MM_ERR_INIT_EMPTY_RAM;
    }
    // align requested size
    size = size + BASE_PAGE_SIZE - (size % BASE_PAGE_SIZE);

    struct mmnode *node;
    for (node = mm->head; node != NULL; node = node->next) {
        if (node->size < size) { continue; }
    }
    if (node == NULL) {
        return MM_ERR_NOT_ENOUGH_RAM;
    }

    // - split cap in requested size
    // - create new mmnode for remaining size, change offset and size
    // - change size of mmnode (node), offset stays the same
    err = mm->slot_alloc(mm->slot_alloc_inst, 1, &retcap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "could not new alloc slot for mm_add\n");
        // TODO-BEAN: implement error push
        return err;
    }
    mm->slot_refill(mm->slot_alloc_inst);
    if (err_is_fail(err)) {
        // TODO-BEAN: push error
        return err;
    }
    err = cap_retype(*retcap, node->cap.cap, node->base, mm->objtype, size, 1);
    if (err_is_fail(err)) {
        // TODO:
        return err;
    }





    DEBUG_END;
    return SYS_ERR_OK;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap) {
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}

errval_t mm_free(struct mm *mm, struct capref cap, genpaddr_t base, gensize_t size) {
    DEBUG_BEGIN;
    // TODO-BEAN: partial free? base addr is not base addr from capability?, fragmentaion?

    DEBUG_END;
    return LIB_ERR_NOT_IMPLEMENTED;
}