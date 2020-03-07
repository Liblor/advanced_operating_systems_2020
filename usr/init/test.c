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

static void test_allocate_ordered(struct mm *mm, const size_t size, const uint32_t bound, const bool reverse)
{
    struct capref caps[bound];

    for (uint32_t i = 0; i < bound; i++)
        caps[i] = test_allocate(mm, size);

    for (uint32_t i = 0; i < bound; i++) {
        const uint32_t idx = (reverse ? bound - 1 - i : i);
        test_free(mm, caps[idx]);
    }
}

void test_libmm(struct mm *mm)
{
    debug_printf("Starting test\n");

    test_allocate_small(mm);
    test_allocate_ordered(mm, 65536, 4 * PAGE_SIZE, false);
    test_allocate_ordered(mm, 65536, 4 * PAGE_SIZE, true);

    debug_printf("Test successfully completed\n");
}
