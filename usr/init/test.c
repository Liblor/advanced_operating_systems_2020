#include <stdio.h>

#include <aos/aos.h>
#include <mm/mm.h>

#include "test.h"

static inline void print_test_begin(const char *name)
{
    debug_printf("################################################################################\n");
    debug_printf("# Begin of test %s\n", name);
}

static inline void print_test_end(const char *name)
{
    debug_printf("End of test %s\n", name);
    debug_printf("################################################################################\n");
}

static inline void print_test_abort(const char *name)
{
    debug_printf("Aborting test %s\n", name);
    debug_printf("################################################################################\n");
}

static struct capref test_allocate(struct mm *mm, const size_t size)
{
    errval_t err;

    const size_t alignment = PAGE_SIZE;
    struct capref cap;

    err = mm_alloc_aligned(mm, size, alignment, &cap);
    assert(err_is_ok(err));

    return cap;
}

static void test_free(struct mm *mm, struct capref cap)
{
    errval_t err;

    struct capability id;
    err = cap_direct_identify(cap, &id);
    assert(err_is_ok(err));

    const genpaddr_t id_base = get_address(&id);
    const gensize_t id_size = get_size(&id);

    err = mm_free(mm, cap, id_base, id_size);
    assert(err_is_ok(err));
}

static void test_allocate_small(struct mm *mm)
{
    debug_printf("test_allocate_small(mm=%p)\n", mm);

    struct capref caps[8];

    caps[0] = test_allocate(mm, PAGE_SIZE);
    caps[1] = test_allocate(mm, PAGE_SIZE);
    caps[2] = test_allocate(mm, 2 * PAGE_SIZE);
    caps[3] = test_allocate(mm, 4 * PAGE_SIZE);
    test_free(mm, caps[2]);
    caps[2] = test_allocate(mm, 2 * PAGE_SIZE);
    test_free(mm, caps[3]);
    caps[3] = test_allocate(mm, 2 * PAGE_SIZE);
    caps[4] = test_allocate(mm, 2 * PAGE_SIZE);
    caps[5] = test_allocate(mm, PAGE_SIZE);
    caps[6] = test_allocate(mm, 4 * PAGE_SIZE);
    test_free(mm, caps[1]);
    test_free(mm, caps[0]);
    test_free(mm, caps[3]);
    test_free(mm, caps[5]);
    caps[1] = test_allocate(mm, PAGE_SIZE);
    caps[0] = test_allocate(mm, 8 * PAGE_SIZE);
    caps[3] = test_allocate(mm, 8 * PAGE_SIZE);
    caps[5] = test_allocate(mm, 2 * PAGE_SIZE);
    caps[7] = test_allocate(mm, 8 * PAGE_SIZE);
    test_free(mm, caps[2]);
    test_free(mm, caps[3]);
    test_free(mm, caps[4]);
    test_free(mm, caps[7]);
    caps[2] = test_allocate(mm, PAGE_SIZE);
    caps[3] = test_allocate(mm, 2 * PAGE_SIZE);
    caps[4] = test_allocate(mm, 4 * PAGE_SIZE);
    caps[7] = test_allocate(mm, PAGE_SIZE);
    test_free(mm, caps[0]);
    test_free(mm, caps[5]);
    test_free(mm, caps[4]);
    test_free(mm, caps[6]);
    test_free(mm, caps[2]);
    test_free(mm, caps[1]);
    test_free(mm, caps[3]);
    test_free(mm, caps[7]);
}

static void test_allocate_ordered(struct mm *mm, const uint32_t count, const size_t size, const bool reverse)
{
    debug_printf("test_allocate_ordered(mm=%p, count=%zd, size=0x%zx, reverse=%d)\n", mm, count, size, reverse);

    struct capref caps[count];

    for (uint32_t i = 0; i < count; i++) {
        debug_printf("Allocation %d of %d\n", i + 1, count);
        caps[i] = test_allocate(mm, size);
    }

    for (uint32_t i = 0; i < count; i++) {
        const uint32_t idx = (reverse ? count - 1 - i : i);
        debug_printf("Free %d of %d\n", i + 1, count);
        test_free(mm, caps[idx]);
    }
}

static void test_add(const uint32_t count, const size_t size)
{
    debug_printf("test_add(count=%"PRIx32", size=0x%zx)\n", count, size);

    errval_t err;

    struct mm mm;

    struct range_slot_allocator init_slot_alloc;

    err = range_slot_alloc_init(&init_slot_alloc, L2_CNODE_SLOTS, NULL);
    assert(err_is_ok(err));

    err = mm_init(
        &mm,
        ObjType_RAM,
        NULL,
        (slot_alloc_t) range_slot_alloc,
        (slot_refill_t) range_slot_alloc_refill,
        &init_slot_alloc
    );
    assert(err_is_ok(err));

    static char nodebuf[sizeof(struct mmnode)*64];
    slab_grow(&mm.slabs, nodebuf, sizeof(nodebuf));

    struct capref caps[count];

    for (int i = 0; i < count; i++) {
        err = ram_alloc(&caps[i], size);
        assert(err_is_ok(err));

        struct capability id;
        err = cap_direct_identify(caps[i], &id);
        assert(err_is_ok(err));

        err = mm_add(&mm, caps[i], get_address(&id), size);
        assert(err_is_ok(err));
    }

    for (uint32_t i = 0; i < count; i++) {
        test_free(&aos_mm, caps[i]);
    }
}

// there are some mistakes with this testsuite, use grading.c version
void test_libmm(void)
{
    print_test_begin("libmm");

    test_add(8, 16 * PAGE_SIZE);

    test_allocate_small(&aos_mm);

    const uint16_t count = 100;

    for (int i = 0; i < count; i++) {
        debug_printf("Executing loop %d of %d\n", i + 1, count);
        test_allocate_ordered(&aos_mm, 20000, 4 * PAGE_SIZE, false);
        test_allocate_ordered(&aos_mm, 20000, 4 * PAGE_SIZE, true);
    }

    print_test_end("libmm");
}

static bool test_paging_multiple(const lvaddr_t base, lvaddr_t *newbase, const int count, const size_t size)
{
    debug_printf("test_paging_multiple(base=%"PRIxLVADDR", newbase=%p, count=%d, size=%zx)\n", base, newbase, count, size);

    errval_t err;

    *newbase = base;
    lvaddr_t vaddr = base;

    for (int i = 0; i < count; i++) {
        struct capref frame_cap;
        size_t bytes = size;

        err = frame_alloc(&frame_cap, bytes, &bytes);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "frame alloc");
            debug_printf("frame_alloc failed: %s\n", err_getstring(err));
            return false;
        }

        *newbase += bytes;

        err = paging_map_fixed_attr(get_current_paging_state(), vaddr, frame_cap, bytes, VREGION_FLAGS_READ_WRITE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "paging_map_fixed_attr");
            debug_printf("paging_map_fixed_attr failed: %s\n", err_getstring(err));
            return false;
        }

        vaddr += bytes;
    }
    for (uint32_t *buf = (uint32_t *) base; (lvaddr_t) buf < vaddr; buf++)
        *buf = 0xAAAAAAAA;

    return true;
}

void test_paging_multi_pagetable(void) {
    print_test_begin("test_paging_multi_pagetable");

    errval_t err;
    uint64_t size = 1024 * 1024 * 1024;

    lvaddr_t *vaddr;
    lvaddr_t base;
    // MAP 1 GB
    for(int i = 0; i < 1; i ++) {
        struct capref frame_cap;
        size_t bytes = size;


        err = frame_alloc(&frame_cap, bytes, &bytes);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "frame_alloc\n");
            debug_printf("frame_alloc failed: %s\n", err_getstring(err));
            assert(false);
        }

        debug_printf("========================================\n");
        debug_printf("mapping %zu at vaddr %p\n", bytes, vaddr);
        err = paging_alloc(get_current_paging_state(), (void **) &vaddr, bytes, BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "paging_alloc failed\n");
            assert(false);
        }
        base = (lvaddr_t ) vaddr;
        err = paging_map_fixed_attr(get_current_paging_state(), base, frame_cap, bytes, VREGION_FLAGS_READ_WRITE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "paging_map_fixed_attr failed\n");
            debug_printf("paging_map_fixed_attr failed: %s\n", err_getstring(err));
            assert(false);
        }
        for (uint32_t *buf = (uint32_t *) base; (lvaddr_t) buf < (base + bytes); buf++)
            *buf = 0xAAAAAAAA;
    }

    assert(true);
}


void test_paging(void)
{
    const char *name = "paging";

    print_test_begin(name);

    // We may not start from VADDR_OFFSET currenty, since the
    // slab_refill_pages() function claims virtual address space starting from
    // there.

    lvaddr_t vaddr = ((lvaddr_t)512UL*1024*1024*1024 * 16); // 16GB

    bool success;

    success = test_paging_multiple(vaddr, &vaddr, 1, BASE_PAGE_SIZE);
    if (!success) {
        print_test_abort(name);
        return;
    }

    success = test_paging_multiple(vaddr, &vaddr, 1, BASE_PAGE_SIZE);
    if (!success) {
        print_test_abort(name);
        return;
    }

    success = test_paging_multiple(vaddr, &vaddr, 4, 4 * BASE_PAGE_SIZE);
    if (!success) {
        print_test_abort(name);
        return;
    }

    // For the next test to work, we need to fill the remaining L3 page
    // directory.
    success = test_paging_multiple(vaddr, &vaddr, 462, BASE_PAGE_SIZE);
    if (!success) {
        print_test_abort(name);
        return;
    }

    success = test_paging_multiple(vaddr, &vaddr, 200, 512 * BASE_PAGE_SIZE);
    if (!success) {
        print_test_abort(name);
        return;
    }

    print_test_end(name);
}
