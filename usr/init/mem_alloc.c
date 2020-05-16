/**
 * \file
 * \brief Local memory allocator for init till mem_serv is ready to use
 */

#include "mem_alloc.h"
#include <mm/mm.h>
#include <aos/paging.h>
#include <collections/range_tracker.h>
#include <grading.h>

/// MM allocator instance data
struct mm aos_mm;

errval_t ram_alloc_aligned_handler(const size_t bytes, const size_t alignment, struct capref *retcap, size_t *retbytes)
{
    errval_t err;

    grading_rpc_handler_ram_cap(bytes, alignment);

    err = ram_alloc_aligned(retcap, bytes, alignment);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "ram_alloc_aligned() failed");
        return err_push(err, LIB_ERR_RAM_ALLOC);
    }

    struct capability cap;
    err = cap_direct_identify(*retcap, &cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "cap_direct_identify() failed");
        return err_push(err, LIB_ERR_CAP_IDENTIFY);
    }

    *retbytes = get_size(&cap);

    return SYS_ERR_OK;
}

errval_t aos_ram_alloc_aligned(struct capref *ret, size_t size, size_t alignment)
{
    return mm_alloc_aligned(&aos_mm, size, alignment, ret);
}

errval_t aos_ram_free(struct capref cap)
{
    errval_t err;

   struct capability c;
    err = cap_direct_identify(cap, &c);
    if (err_is_fail(err)) {
        return err;
    }

    return mm_free(&aos_mm, cap, get_address(&c), get_size(&c));
}

static inline errval_t initialize_ram_allocator(void)
{
    errval_t err;

    // Init slot allocator
    static struct slot_prealloc init_slot_alloc;
    struct capref cnode_cap = {
        .cnode = {
            .croot = CPTR_ROOTCN,
            .cnode = ROOTCN_SLOT_ADDR(ROOTCN_SLOT_SLOT_ALLOC0),
            .level = CNODE_TYPE_OTHER,
        },
        .slot = 0,
    };
    err = slot_prealloc_init(&init_slot_alloc, cnode_cap, L2_CNODE_SLOTS, &aos_mm);
    if (err_is_fail(err)) {
        return err_push(err, MM_ERR_SLOT_ALLOC_INIT);
    }

    // Initialize aos_mm
    err = mm_init(&aos_mm, ObjType_RAM, NULL,
                  slot_alloc_prealloc, slot_prealloc_refill,
                  &init_slot_alloc);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "Can't initalize the memory manager.");
    }

    // Give aos_mm a bit of memory for the initialization
    static char nodebuf[RANGE_TRACKER_NODE_SIZE*64];
    slab_grow(&aos_mm.slabs, nodebuf, sizeof(nodebuf));

    return SYS_ERR_OK;
}

/**
 * \brief Setups a local memory allocator for init to use till the memory server
 * is ready to be used. Inspects bootinfo for finding memory region.
 */
errval_t initialize_ram_alloc(size_t num_cores)
{
    errval_t err;

    err = initialize_ram_allocator();
    if (err_is_fail(err)) {
        return err;
    }

    // Walk bootinfo and add all RAM caps to allocator handed to us by the kernel
    uint64_t mem_avail = 0;
    struct capref mem_cap = {
        .cnode = cnode_super,
        .slot = 0,
    };

    for (int i = 0; i < bi->regions_length; i++) {
        if (bi->regions[i].mr_type == RegionType_Empty) {
            gensize_t mr_bytes = bi->regions[i].mr_bytes / num_cores;
            // TODO: Fix
            genpaddr_t base = ROUND_UP(bi->regions[i].mr_base + disp_get_core_id() * mr_bytes, BASE_PAGE_SIZE);
            err = mm_add(&aos_mm, mem_cap, base, mr_bytes);
            if (err_is_ok(err)) {
                mem_avail += mr_bytes;
            } else {
                DEBUG_ERR(err, "Warning: adding RAM region %d (%p/%zu) FAILED", i, bi->regions[i].mr_base, bi->regions[i].mr_bytes);
            }

            err = slot_prealloc_refill(aos_mm.slot_alloc_inst);
            if (err_is_fail(err) && err_no(err) != MM_ERR_SLOT_MM_ALLOC) {
                DEBUG_ERR(err, "in slot_prealloc_refill() while initialising memory allocator");
                abort();
            }

            mem_cap.slot++;
        }
    }
    debug_printf("Added %"PRIu64" MB of physical memory.\n", mem_avail / 1024 / 1024);

    // Finally, we can initialize the generic RAM allocator to use our local allocator
    err = ram_alloc_set(aos_ram_alloc_aligned);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RAM_ALLOC_SET);
    }

    return SYS_ERR_OK;
}

