#include <aos/paging.h>
#include <aos/domain.h>
#include "minunit.h"


MU_TEST(map_arbitrary_addresses) {
    struct capref frame;
    size_t bytes = 4*BASE_PAGE_SIZE;

    errval_t err = frame_alloc(&frame, bytes, &bytes);
    char *buf1 = (char *)0xFFFF00000000;
    mu_assert(err_is_ok(err), "frame alloc shouldn't have failed\n");
    err = paging_map_fixed_attr(get_current_paging_state(), (lvaddr_t)buf1, frame,
            bytes, VREGION_FLAGS_READ_WRITE);
    mu_assert(err_is_ok(err), "paging_map_fixed failed\n");

    for (int i = 0; i < bytes; i++) {
        buf1[i] = 0xff;
    }
}

static errval_t map_bytes_at_addr(lvaddr_t* base, uint64_t bytes) {
    errval_t err;
    struct capref frame_cap;

    err = frame_alloc(&frame_cap, bytes, &bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "frame alloc");
        debug_printf("frame_alloc failed: %s\n", err_getstring(err));
        mu_assert(false);
    }
    err = paging_map_fixed_attr(get_current_paging_state(), *base, frame_cap, bytes, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_map_fixed_attr failed\n");
        debug_printf("paging_map_fixed_attr failed: %s\n", err_getstring(err));
        mu_assert(false);
    }
    for (uint32_t *buf = (uint32_t *) *base; (lvaddr_t) buf < (*base + bytes); buf++)
        *buf = 0xAAAAAAAA;

    *base += bytes;

    return SYS_ERR_OK;
}

MU_TEST(test_paging__cause_errors) {
    struct capref frame_cap;
    mu_assert(err_is_fail(paging_map_fixed_attr(get_current_paging_state(),
            BASE_PAGE_SIZE * 1024, frame_cap, 0, VREGION_FLAGS_READ_WRITE)));
    mu_assert(err_is_fail(paging_map_fixed_attr(get_current_paging_state(),
            0, frame_cap, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE)));
    mu_assert(err_is_fail(paging_map_fixed_attr(get_current_paging_state(),
            BASE_PAGE_SIZE + 1, frame_cap, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE)));
}

MU_TEST(test_paging__map_fixed_attr_with_gabs) {
    errval_t err;
    uint64_t size;
    lvaddr_t vaddr = ((lvaddr_t)512UL*1024*1024*1024 * 32);

    lvaddr_t base = vaddr;
    for(int i = 0; i < BASE_PAGE_SIZE; i ++) {
        size = BASE_PAGE_SIZE * (i % 9) + 17; // not aligned size
        err = map_bytes_at_addr(&base, size);
        if (!err_is_ok(err)) {
            DEBUG_ERR(err, "error in test_paging_multi_pagetable\n");
            mu_assert(false);
        }
        base += BASE_PAGE_SIZE * (i % 128); // some gap between
    }
    mu_assert(true);

    mu_assert(base < vaddr * 2); // dont trash space for other tests
}

