#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <mm/mm.h>
#include <grading.h>


int tests_run = 0;
#define start_test debug_printf("running %s \n",  __FUNCTION__)
#define test_assert(message, test) { if (!(test)) return message; }
#define test_run(test) { char *message = test(); tests_run++; \
                                if (message) return message; }

static struct bootinfo * bi;
void testbench(struct bootinfo *);

// --------------------------------------------------
// setup
// --------------------------------------------------
errval_t init_and_add_mem_to_mm(struct mm *, struct slot_prealloc *);

errval_t init_and_add_mem_to_mm(struct mm *aos_mm0, struct slot_prealloc *init_slot_alloc) {
    errval_t err;
    struct mm aos_mm = *aos_mm0;

    // Init slot allocator
    // cnode_cap is a reference to a l2c cnode
    struct capref cnode_cap = {
            .cnode = {
                    .croot = CPTR_ROOTCN,
                    .cnode = ROOTCN_SLOT_ADDR(ROOTCN_SLOT_SLOT_ALLOC0),
                    .level = CNODE_TYPE_OTHER,
            },
            .slot = 0,
    };
    err = slot_prealloc_init(init_slot_alloc, cnode_cap, L2_CNODE_SLOTS, &aos_mm);
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
    DEBUG_PRINTF("size of mmnode: %d\n", sizeof(struct mmnode));
    static char nodebuf[sizeof(struct mmnode) * 64];
    slab_grow(&aos_mm.slabs, nodebuf, sizeof(nodebuf));

    // Walk bootinfo and add all RAM caps to allocator handed to us by the kernel
    uint64_t mem_avail = 0;
    struct capref mem_cap = {
            .cnode = cnode_super,
            .slot = 0,
    };

    for (int i = 0; i < bi->regions_length; i++) {
        if (bi->regions[i].mr_type == RegionType_Empty) {
            err = mm_add(&aos_mm, mem_cap, bi->regions[i].mr_base, bi->regions[i].mr_bytes);
            if (err_is_ok(err)) {
                mem_avail += bi->regions[i].mr_bytes;
            } else {
                DEBUG_ERR(err, "Warning: adding RAM region %d (%p/%zu) FAILED", i, bi->regions[i].mr_base,
                          bi->regions[i].mr_bytes);
            }

            err = slot_prealloc_refill(aos_mm.slot_alloc_inst);
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
//    err = ram_alloc_set(aos_ram_alloc_aligned);
//    if (err_is_fail(err)) {
//        return err_push(err, LIB_ERR_RAM_ALLOC_SET);
//    }
    return SYS_ERR_OK;
}

// --------------------------------------------------
// TEST MM_INIT
// --------------------------------------------------
char *test_mm_init(void);

char *test_mm_init(void) {
    start_test;

    // setup
    struct mm mm;
    struct slot_prealloc aos_test_init_slot_alloc;
    errval_t err;

    struct capref cnode_cap = {
            .cnode = {
                    .croot = CPTR_ROOTCN,
                    .cnode = ROOTCN_SLOT_ADDR(ROOTCN_SLOT_SLOT_ALLOC0),
                    .level = CNODE_TYPE_OTHER,
            },
            .slot = 0,
    };
    err = slot_prealloc_init(&aos_test_init_slot_alloc, cnode_cap, L2_CNODE_SLOTS, &mm);
    if (err_is_fail(err)) {
        test_assert("slot prealloc init failed", false);
    }

    err = mm_init(&mm, ObjType_RAM, NULL,
                  slot_alloc_prealloc, slot_prealloc_refill,
                  &aos_test_init_slot_alloc);

    test_assert("err_is_ok wrong", err_is_ok(err));
    test_assert("mm.slot_refill != slot_prealloc_refill)", mm.slot_refill == slot_prealloc_refill);
    test_assert("mm.slot_alloc_inst != &aos_test_init_slot_alloc)", mm.slot_alloc_inst == &aos_test_init_slot_alloc);
    test_assert("mm.slot_alloc != slot_alloc_prealloc)", mm.slot_alloc == slot_alloc_prealloc);
    test_assert("mm.objtype != ObjType_RAM)", mm.objtype == ObjType_RAM);

    return 0;
}

// --------------------------------------------------
// TEST MM_ADD
// --------------------------------------------------
char *test_mm_add(void);
char *test_mm_add(void) {
    struct mm aos_mm;
    struct slot_prealloc init_slot_alloc;
    errval_t err;

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
        test_assert("failed slot prealloc init", false);
    }
    err = mm_init(&aos_mm, ObjType_RAM, NULL,
                  slot_alloc_prealloc, slot_prealloc_refill,
                  &init_slot_alloc);
    if (err_is_fail(err)) {
        test_assert("Can't initalize the memory manager.", false);
    }
    static char nodebuf[sizeof(struct mmnode) * 64];
    slab_grow(&aos_mm.slabs, nodebuf, sizeof(nodebuf));
    uint64_t mem_avail = 0;
    struct capref mem_cap = {
            .cnode = cnode_super,
            .slot = 0,
    };
    for (int i = 0; i < bi->regions_length; i++) {
        if (bi->regions[i].mr_type == RegionType_Empty) {
            err = mm_add(&aos_mm, mem_cap, bi->regions[i].mr_base, bi->regions[i].mr_bytes);
//            test_assert() TODO
            if (err_is_ok(err)) {
                mem_avail += bi->regions[i].mr_bytes;
            } else {
                test_assert("Warning: adding RAM region %d (%p/%zu) FAILED", false);
            }

            err = slot_prealloc_refill(aos_mm.slot_alloc_inst);
            if (err_is_fail(err) && err_no(err) != MM_ERR_SLOT_MM_ALLOC) {
                test_assert("in slot_prealloc_refill() while initialising memory allocator", false);
            }

            mem_cap.slot++;
        }
    }
    debug_printf("Added %"PRIu64" MB of physical memory.\n", mem_avail / 1024 / 1024);

    return 0;
}

// --------------------------------------------------
// TESTS
// --------------------------------------------------

char *all_tests(void);
char *all_tests(void) {
    test_run(test_mm_init);
    test_run(test_mm_add);
    return 0;
}

void testbench(struct bootinfo *bi0) {
    bi = bi0;
    char *result = all_tests();
    if (result != 0) {
        DEBUG_PRINTF("%s\n", result);
    } else {
        DEBUG_PRINTF("ALL TESTS PASSED\n");
    }
    DEBUG_PRINTF("Tests run: %d\n", tests_run);
}
