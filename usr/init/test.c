#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <mm/mm.h>
#include <grading.h>

static struct mm aos_test_mm;
static struct slot_prealloc aos_test_init_slot_alloc;

void setup() {
    errval_t initialize_ram_alloc(void) {
        errval_t err;

        struct capref cnode_cap = {
                .cnode = {
                        .croot = CPTR_ROOTCN,
                        .cnode = ROOTCN_SLOT_ADDR(ROOTCN_SLOT_SLOT_ALLOC0),
                        .level = CNODE_TYPE_OTHER,
                },
                .slot = 0,
        };
        err = slot_prealloc_init(&aos_test_init_slot_alloc, cnode_cap, L2_CNODE_SLOTS, &aos_test_mm);
        if (err_is_fail(err)) {
            return err_push(err, MM_ERR_SLOT_ALLOC_INIT);
        }

        // Initialize aos_test_mm
        err = mm_init(&aos_test_mm, ObjType_RAM, NULL,
                      slot_alloc_prealloc, slot_prealloc_refill,
                      &aos_test_init_slot_alloc);

        if (err_is_fail(err)) {
            USER_PANIC_ERR(err, "Can't initalize the memory manager.");
        }

        // Give aos_test_mm a bit of memory for the initialization
        DEBUG_PRINTF("size of mmnode: %d\n", sizeof(struct mmnode));
        static char nodebuf[sizeof(struct mmnode) * 64];
        slab_grow(&aos_test_mm.slabs, nodebuf, sizeof(nodebuf));

        // Walk bootinfo and add all RAM caps to allocator handed to us by the kernel
        uint64_t mem_avail = 0;
        struct capref mem_cap = {
                .cnode = cnode_super,
                .slot = 0,
        };

        for (int i = 0; i < bi->regions_length; i++) {
            if (bi->regions[i].mr_type == RegionType_Empty) {
                err = mm_add(&aos_test_mm, mem_cap, bi->regions[i].mr_base, bi->regions[i].mr_bytes);

                if (err_is_ok(err)) {
                    mem_avail += bi->regions[i].mr_bytes;
                } else {
                    DEBUG_ERR(err, "Warning: adding RAM region %d (%p/%zu) FAILED", i, bi->regions[i].mr_base,
                              bi->regions[i].mr_bytes);
                }

                err = slot_prealloc_refill(aos_test_mm.slot_alloc_inst);
                if (err_is_fail(err) && err_no(err) != MM_ERR_SLOT_MM_ALLOC) {
                    DEBUG_ERR(err, "in slot_prealloc_refill() while initialising"
                                   " memory allocator");
                    abort();
                }

                mem_cap.slot++;
            }
        }
        debug_printf("Added %"PRIu64" MB of physical memory.\n", mem_avail / 1024 / 1024);

        // Finally, we can initialize the generic RAM allocator to use our local allocator
//        err = ram_alloc_set(aos_ram_alloc_aligned);
//        if (err_is_fail(err)) {
//            return err_push(err, LIB_ERR_RAM_ALLOC_SET);
//        }

        return SYS_ERR_OK;
    }
}


void test_suites() {
//    setup();
    test_mm_init();
}

void test_mm_init() {
//    err = mm_init(&aos_test_mm, ObjType_RAM, NULL,
//                  slot_alloc_prealloc, slot_prealloc_refill,
//                  &aos_test_init_slot_alloc);

//    aos_test_mm;
}