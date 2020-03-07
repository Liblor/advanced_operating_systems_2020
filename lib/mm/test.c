#include <errors/errno.h>
#include <stdio.h>
#include <aos/aos.h>
#include <aos/debug.h>
#include <mm/mm.h>
#include <mm/test.h>



static struct bootinfo *bi;

static void evaluate_result(struct mm *mm, errval_t err, bool expect_success) {
    if (expect_success) {
        if (err_is_ok(err)) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            DEBUG_ERR(err, "Call should succeed.");
        }
    } else {
        if (err_is_fail(err)) {
            printf("OK\n");
        } else {
            printf("FAIL, call should fail");
        }
    }

    if (expect_success)
        mm_print_state(mm);
}

static void mm_test_add(struct mm *mm, struct capref *cap, genpaddr_t position, size_t size, bool expect_success) {
    //bi->regions[0].mr_bytes
    genpaddr_t base = bi->regions[0].mr_base + position;

    printf("Testing mm_add(), base=%p, size=%d --- ", base, size);
    errval_t err = mm_add(mm, *cap, base, size);
    evaluate_result(mm, err, expect_success);
}

static void mm_test_alloc_aligned(struct mm *mm, size_t alignment, size_t size, struct capref *retcap, bool expect_success) {
    printf("Testing mm_alloc_aligned(), alignment=%d, size=%d --- ", alignment, size);
    errval_t err = mm_alloc_aligned(mm, size, alignment, retcap);
    evaluate_result(mm, err, expect_success);
}

void mm_test_run1(struct bootinfo *b) {
    bi = b;

    errval_t err;
    struct mm aos_mm;

    // Taken from mem_alloc.c
    //##################
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
        USER_PANIC_ERR(err, "Can't initalize the slot allocator.");
    }

    // Initialize aos_mm
    err = mm_init(&aos_mm, ObjType_RAM, NULL, slot_alloc_prealloc, slot_prealloc_refill, &init_slot_alloc);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "Can't initalize the memory manager.");
    }

    // Give aos_mm a bit of memory for the initialization
    static char nodebuf[sizeof(struct mmnode)*64];
    slab_grow(&aos_mm.slabs, nodebuf, sizeof(nodebuf));

    // Walk bootinfo and add all RAM caps to allocator handed to us by the kernel
    struct capref mem_cap = {
        .cnode = cnode_super,
        .slot = 0,
    };
    //##################


    mm_test_add(&aos_mm, &mem_cap, 0x10, 16, true);
    mm_test_add(&aos_mm, &mem_cap, 0x10, 16, false);
    mm_test_add(&aos_mm, &mem_cap, 0x30, 16, true);
    mm_test_add(&aos_mm, &mem_cap, 0x2f, 2, false);
    mm_test_add(&aos_mm, &mem_cap, 0x40-1, 1, false);
    mm_test_add(&aos_mm, &mem_cap, 0x40, 1, true);
    mm_test_add(&aos_mm, &mem_cap, 0x2f, 1, true);
    mm_test_add(&aos_mm, &mem_cap, 0x20, 15, true);
    mm_test_add(&aos_mm, &mem_cap, 0x50, 16, true);
    mm_test_add(&aos_mm, &mem_cap, 0x50, 16, false);
    mm_test_add(&aos_mm, &mem_cap, 0x50, 1, false);
    mm_test_add(&aos_mm, &mem_cap, 0x52, 4, false);
    mm_test_add(&aos_mm, &mem_cap, 0x08, 8, true);
    mm_test_add(&aos_mm, &mem_cap, 0x00, 8, true);

    printf("######## CHECK THE OUTPUT FOR CORRECTNESS ########\n");
}

void mm_test_run2(struct mm *mm) {
    struct capref caps[10];

    mm_test_alloc_aligned(mm, 4, 5, &caps[0], true);
    mm_test_alloc_aligned(mm, 4, 5, &caps[1], true);

    printf("######## CHECK THE OUTPUT FOR CORRECTNESS ########\n");
}
