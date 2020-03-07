/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
 */

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>

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
                     void *slot_alloc_inst)
{
    DEBUG_BEGIN;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc_inst =  slot_alloc_inst;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc = slot_alloc_func;
    mm->objtype = objtype;

//    TODO: what to do with slab, what block size? check that not too small
    slab_init(&mm->slabs, 1 << 10, slab_refill_func); // 1kib block size
    mm->slabs.refill_func = slab_refill_func;

    DEBUG_END;
    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm)
{
    DEBUG_BEGIN;
    assert(!"NYI");
    DEBUG_END;
}

errval_t mm_add(struct mm *mm, struct capref cap, genpaddr_t base, size_t size)
{
    DEBUG_BEGIN;
//    struct mmnode {
//        enum nodetype type;    ///< Type of `this` node.
//        struct capinfo cap;    ///< Cap in which this region exists
//        struct mmnode *prev;   ///< Previous node in the list.
//        struct mmnode *next;   ///< Next node in the list.
//        genpaddr_t base;       ///< Base address of this region
//        gensize_t size;        ///< Size of this free region in cap
//    };

    struct mmnode* node = slab_alloc(&mm->slabs);
    node->type = NodeType_Free;
    node->next;
    node->prev;
    node->size;

    //TODO: unclear
    node->base = base;

    node->cap.cap = cap;
    node->cap.base = base;
    node->cap.size = size; // TODO: difference to node->base

    // TODO:
    // add caps to list
    // how to do splitting, should we add them as there are, and do splitting in alloc?
    DEBUG_END;
    return LIB_ERR_NOT_IMPLEMENTED;
}


errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap)
{
    DEBUG_BEGIN;
    DEBUG_END;
    return LIB_ERR_NOT_IMPLEMENTED;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}


errval_t mm_free(struct mm *mm, struct capref cap, genpaddr_t base, gensize_t size)
{
    DEBUG_BEGIN;
    DEBUG_END;
    return LIB_ERR_NOT_IMPLEMENTED;

}
