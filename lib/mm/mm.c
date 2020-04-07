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

    slab_init(&mm->slabs, RANGE_TRACKER_NODE_SIZE, slab_refill_func);

    return range_tracker_init(&mm->rt, &mm->slabs);
}

void mm_destroy(struct mm *mm)
{
    assert(!"NYI");
}

void mm_print_state(struct mm *mm) {
    range_tracker_print_state(&mm->rt);
}

errval_t mm_add(struct mm *mm, struct capref cap, genpaddr_t base, size_t size)
{
    assert(mm != NULL);

    errval_t err;

    union range_tracker_shared shared;
    shared.cap = cap;
    err = range_tracker_add(&mm->rt, base, size, shared);

    return err;
}

errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment, struct capref *retcap)
{
    assert(mm != NULL);

    errval_t err;

    if (size == 0)
        return MM_ERR_INVALID_SIZE;

    if (alignment == 0 || alignment % BASE_PAGE_SIZE != 0)
        return MM_ERR_INVALID_ALIGNMENT;


    struct rtnode *new_node = NULL;
    err = range_tracker_alloc_aligned(&mm->rt, size, alignment, &new_node);
    if (err_is_fail(err)) {
        return err;
    }

    // Retype the aligned part of the node with the requested size.
    err = mm->slot_alloc(mm->slot_alloc_inst, 1, retcap);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_SLOT_ALLOC);
        goto error_recovery;
    }

    struct capref original_cap = new_node->shared.cap;
    struct capability original_cap_id;

    err = cap_direct_identify(original_cap, &original_cap_id);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "cap_direct_identify failed");
        goto error_recovery;
    }

    genpaddr_t original_base = get_address(&original_cap_id);

    err = cap_retype(*retcap, original_cap, new_node->base - original_base, mm->objtype, size, 1);
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

    return SYS_ERR_OK;

error_recovery:
    // TODO Free the allocated node in the range_tracker again
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

    err = range_tracker_free(&mm->rt, base, size, MKRTCLOSURE(NULL, NULL));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "range_tracker_free() failed");
        return err;
    }

    return SYS_ERR_OK;
}
