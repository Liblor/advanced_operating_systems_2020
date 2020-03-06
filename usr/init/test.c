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

void test_libmm(struct mm *mm)
{
    debug_printf("Starting test\n");

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

    debug_printf("Test successfully completed\n");
}
