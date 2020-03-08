#include <stdio.h>

#include <aos/aos.h>
#include <mm/mm.h>

#include "test.h"

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
    debug_printf("test_allocate_small(mm=%p, count=%zd, size=0x%zx, reverse=%d)\n", mm, count, size, reverse);

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

void test_libmm(void)
{
    debug_printf("Starting test\n");

    test_add(8, 16 * PAGE_SIZE);

    test_allocate_small(&aos_mm);

    // TODO: Increase count to 65536 once the slabs can dynamically grow.
    test_allocate_ordered(&aos_mm, 64, 4 * PAGE_SIZE, false);
    test_allocate_ordered(&aos_mm, 64, 4 * PAGE_SIZE, true);

    debug_printf("Test successfully completed\n");
}
