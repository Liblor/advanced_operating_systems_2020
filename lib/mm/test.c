#include <errors/errno.h>
#include <stdio.h>
#include <aos/aos.h>
#include <aos/debug.h>
#include <mm/mm.h>
#include <mm/test.h>



static struct bootinfo *bi;

static void evaluate_result(struct mm *mm, errval_t err, errval_t err_expected, bool suppress_output) {
    if (err == err_expected) {
        if (!suppress_output)
            printf("OK\n");
    } else {
        printf("FAIL\n");
        printf("Call returned in %s (expected %s)\n", err_getcode(err), err_getcode(err_expected));
    }

    if (mm != NULL && err_expected == SYS_ERR_OK && !suppress_output)
        mm_print_state(mm);
}

static void mm_test_add(struct mm *mm, struct capref *cap, genpaddr_t position, size_t size, bool expect_success) {
    genpaddr_t base = bi->regions[4].mr_base + position;

    debug_printf("Testing mm_add(), base=%p, size=%u --- ", base, size);
    errval_t err = mm_add(mm, *cap, base, size);
    evaluate_result(mm, err, SYS_ERR_OK, false);
}

static void mm_test_alloc_aligned(struct mm *mm, size_t alignment, size_t size, struct capref *retcap, bool expect_success) {
    debug_printf("Testing mm_alloc_aligned(), alignment=%d, size=%u --- ", alignment, size);
    errval_t err = mm_alloc_aligned(mm, size, alignment, retcap);
    evaluate_result(mm, err, SYS_ERR_OK, false);
    if (err_is_ok(err))
        debug_printf("retcap: %p > %p > %u\n", retcap->cnode.croot, retcap->cnode.cnode, retcap->slot);
}

static void mm_test_free(struct mm *mm, struct capref cap, bool expect_success) {
    errval_t err;
    struct capability capability;

    err = cap_direct_identify(cap, &capability);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "cap_direct_identify failed");
        return;
    }

    genpaddr_t base = get_address(&capability);
    gensize_t size = get_size(&capability);

    debug_printf("Testing mm_test_free(), base=%p, size=%u --- ", base, size);
    err = mm_free(mm, cap, base, size);
    evaluate_result(mm, err, SYS_ERR_OK, false);
}

void mm_test_run1(struct bootinfo *b) {
    errval_t err;
    struct mm aos_mm;

    bi = b;

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

    // Current version passes
    debug_printf("################ CHECK THE OUTPUT FOR CORRECTNESS ################\n");
}

void mm_test_run2(struct bootinfo *b, struct mm *mm) {
    bi = b;
    size_t space = bi->regions[4].mr_bytes - 16384;

    struct capref caps[10];

    // Current version passes
    debug_printf("########################### SECTION 1 ############################\n");

    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 1, &caps[0], true);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 2, &caps[1], true);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 3, &caps[2], true);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4, &caps[3], true);
    mm_test_free(mm, caps[0], true);
    mm_test_free(mm, caps[1], true);
    mm_test_free(mm, caps[2], true);
    mm_test_free(mm, caps[3], true);

    // Current version passes
    debug_printf("########################### SECTION 2 ############################\n");

    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, space - 4096, &caps[0], true);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4096, &caps[1], true);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 1, &caps[2], false);
    mm_test_free(mm, caps[1], true);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 1, &caps[3], true);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 1, &caps[4], false);
    mm_test_free(mm, caps[3], true);

    debug_printf("########################### SECTION 3 ############################\n");

    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4096*16, &caps[0], true);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, space - 4096*16, &caps[1], true);
    mm_test_free(mm, caps[0], true);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4096*4, &caps[2], false);
    mm_test_free(mm, caps[2], true);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE*3, 4096*16, &caps[3], false);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE*3, 4096, &caps[4], true);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4096, &caps[5], true);
    mm_test_free(mm, caps[3], true);
    mm_test_free(mm, caps[4], true);
    mm_test_free(mm, caps[1], true);
    mm_test_free(mm, caps[5], true);

    debug_printf("########################### SECTION 4 ############################\n");
    // TODO test free throughly
    // TODO Check if all paths of alloc are covered
    // TODO Check many alloc calls to have case where slot allocator runs out of slots and needs to be refilled

    debug_printf("################ CHECK THE OUTPUT FOR CORRECTNESS ################\n");
}

static void paging_test_map_fixed_attr(lvaddr_t vaddr, size_t size, errval_t err_expected, bool suppress_output) {
    errval_t err;

    if (!suppress_output)
        debug_printf("Testing paging_map_fixed_attr(), vaddr=%p, size=%u --- ", vaddr, size);

    struct capref frame_cap;
    size_t frame_size;

    err = frame_alloc(&frame_cap, size, &frame_size);
    if (err_is_fail(err))
        DEBUG_ERR(err, "frame_alloc() failed");

    err = paging_map_fixed_attr(get_current_paging_state(), vaddr, frame_cap, frame_size, VREGION_FLAGS_READ_WRITE);

    evaluate_result(NULL, err, err_expected, suppress_output);

    if (err == SYS_ERR_OK) {
        uint8_t *page = ((uint8_t *) vaddr);
        for (int i = 0; i < size; i++) {
            page[i] = 0xff;
        }
    }
}

static lvaddr_t offset = 100;

static void paging_test_single(void) {
    debug_printf("####################### paging_test_single #######################\n");
    paging_test_map_fixed_attr(VADDR_OFFSET + BASE_PAGE_SIZE * offset, BASE_PAGE_SIZE, SYS_ERR_OK, false);
    offset++;
}

static void paging_test_multiple(void) {
    debug_printf("###################### paging_test_multiple ######################\n");
    int i;
    for (i = 0; i < 2; i++) {
        paging_test_map_fixed_attr(VADDR_OFFSET + BASE_PAGE_SIZE * (offset + i), BASE_PAGE_SIZE, SYS_ERR_OK, false);
    }
    offset += i;
}

static void paging_test_double_map(void) {
    debug_printf("##################### paging_test_double_map #####################\n");
    paging_test_map_fixed_attr(VADDR_OFFSET + BASE_PAGE_SIZE * offset, BASE_PAGE_SIZE, SYS_ERR_OK, false);
    paging_test_map_fixed_attr(VADDR_OFFSET + BASE_PAGE_SIZE * offset, BASE_PAGE_SIZE, LIB_ERR_VSPACE_PAGE_ALREADY_MAPPED, false);
    offset += 1;
}

static void paging_test_double_map_range(void) {
    debug_printf("################## paging_test_double_map_range ##################\n");
    lvaddr_t local_offset = VADDR_OFFSET + BASE_PAGE_SIZE * offset;
    paging_test_map_fixed_attr(local_offset + BASE_PAGE_SIZE * 2, BASE_PAGE_SIZE * 10, SYS_ERR_OK, false);
    paging_test_map_fixed_attr(local_offset, BASE_PAGE_SIZE * 3, LIB_ERR_VSPACE_PAGE_ALREADY_MAPPED, false);
    paging_test_map_fixed_attr(local_offset + BASE_PAGE_SIZE * 11, BASE_PAGE_SIZE * 3, LIB_ERR_VSPACE_PAGE_ALREADY_MAPPED, false);
    paging_test_map_fixed_attr(local_offset, BASE_PAGE_SIZE * 2, SYS_ERR_OK, false);
    paging_test_map_fixed_attr(local_offset + BASE_PAGE_SIZE * 12, BASE_PAGE_SIZE * 2, SYS_ERR_OK, false);
    offset += 14;
}

static void paging_test_1g(void) {
    debug_printf("######################### paging_test_1g #########################\n");
    uint64_t pages_1g = 1024*1024*1024 / BASE_PAGE_SIZE;

    uint64_t remainder = offset % PTABLE_ENTRIES;
    uint64_t to_full_l3 = 0;
    if (remainder != 0)
        to_full_l3 = PTABLE_ENTRIES - remainder;

    debug_printf("Testing paging_map_fixed_attr() by mapping %u remaining pages (%u MB) --- ", pages_1g - offset, (pages_1g - offset) * 4096 / 1024 / 1024);

    paging_test_map_fixed_attr(VADDR_OFFSET + BASE_PAGE_SIZE * offset, BASE_PAGE_SIZE * to_full_l3, SYS_ERR_OK, true);
    offset += to_full_l3;

    while (offset < pages_1g) {
        paging_test_map_fixed_attr(VADDR_OFFSET + BASE_PAGE_SIZE * offset, BASE_PAGE_SIZE * PTABLE_ENTRIES, SYS_ERR_OK, true);
        offset += PTABLE_ENTRIES;
    }

    assert(offset == pages_1g);
    printf("OK\n");
    err_print_calltrace(SYS_ERR_OK);
}

void paging_test_run1(void) {
    paging_test_single();
    paging_test_multiple();
    paging_test_double_map();
    paging_test_double_map_range();
    paging_test_1g();
}
