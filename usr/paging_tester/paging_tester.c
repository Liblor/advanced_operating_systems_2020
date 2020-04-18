#include <stdio.h>

#include <aos/aos.h>

//#define err_is_fail(err) ((err_is_fail(err) ? (DEBUG_ERR(err, err_getstring(err)), true) : false))

__unused
static inline errval_t _create_map_write_frame(lvaddr_t vaddr, size_t bytes)
{
    struct capref frame;
    char *buf1 = (char *) vaddr;

    errval_t err = frame_alloc(&frame, bytes, &bytes);
    if (err_is_fail(err)) {
        return err;
    }
    err = paging_map_fixed_attr(get_current_paging_state(),
                                (lvaddr_t) buf1,
                                frame,
                                bytes,
                                VREGION_FLAGS_READ_WRITE);

    if (err_is_ok(err)) {
        return err;
    }
    for (int i = 0; i < bytes; i++) {
        buf1[i] = 0xff;
    }

    return SYS_ERR_OK;
}

__unused
static errval_t map_arbitrary_addresses(void)
{
    errval_t err;
    err = _create_map_write_frame(0xFFFF00000000, 4 * BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err;
    }
    err = _create_map_write_frame(0xEFFF00000000, 2 * BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err;
    }
    err = _create_map_write_frame(0xEFF305500000, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err;
    }
    err = _create_map_write_frame(0xE1F305500000, 64 * BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

__unused
static errval_t _map_bytes_at_addr(lvaddr_t *base, uint64_t bytes)
{
    errval_t err;
    struct capref frame_cap;

    err = frame_alloc(&frame_cap, bytes, &bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "frame alloc");
        debug_printf("frame_alloc failed: %s\n", err_getstring(err));
        return err;
    }
    err = paging_map_fixed_attr(get_current_paging_state(),
                                *base,
                                frame_cap,
                                bytes,
                                VREGION_FLAGS_READ_WRITE);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_map_fixed_attr failed\n");
        debug_printf("paging_map_fixed_attr failed: %s\n", err_getstring(err));
        return err;
    }
    for (uint32_t *buf = (uint32_t *) *base; (lvaddr_t) buf < (*base + bytes); buf++)
        *buf = 0xAAAAAAAA;

    *base += bytes;

    return SYS_ERR_OK;
}

__unused
static errval_t test_paging__cause_errors(void)
{
    errval_t err;
    struct capref frame_cap;
    err = paging_map_fixed_attr(get_current_paging_state(),
                                BASE_PAGE_SIZE * 1024,
                                frame_cap,
                                0,
                                VREGION_FLAGS_READ_WRITE);

    assert(!err_is_ok(err));

    assert(!err_is_ok(paging_map_fixed_attr(get_current_paging_state(),
                                            0,
                                            frame_cap,
                                            BASE_PAGE_SIZE,
                                            VREGION_FLAGS_READ_WRITE)));


    assert(!err_is_ok(paging_map_fixed_attr(get_current_paging_state(),
                                            BASE_PAGE_SIZE + 1,
                                            frame_cap,
                                            BASE_PAGE_SIZE,
                                            VREGION_FLAGS_READ_WRITE)));

    return SYS_ERR_OK;
}


__unused
static errval_t test_paging__map_fixed_attr_with_gabs(void)
{
    errval_t err;
    uint64_t size;
    lvaddr_t vaddr = ((lvaddr_t) 512UL * 1024 * 1024 * 1024 * 32);

    lvaddr_t base = vaddr;
    for (int i = 0; i < BASE_PAGE_SIZE; i++) {
        size = BASE_PAGE_SIZE * (i % 9) + 17; // not aligned size
        err = _map_bytes_at_addr(&base, size);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "error in test_paging_multi_pagetable\n");
            return err;
        }
        base += BASE_PAGE_SIZE * (i % 128); // some gap between
    }
    return SYS_ERR_OK;
}


static errval_t
_test_paging_multiple(const lvaddr_t base, lvaddr_t *newbase, const int count, const size_t size)
{
    debug_printf("_test_paging_multiple(base=%"PRIxLVADDR", newbase=%p, count=%d, size=%zx)\n",
                 base,
                 newbase, count, size);

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
            return err;
        }

        *newbase += bytes;

        err = paging_map_fixed_attr(get_current_paging_state(), vaddr, frame_cap, bytes,
                                    VREGION_FLAGS_READ_WRITE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "paging_map_fixed_attr");
            debug_printf("paging_map_fixed_attr failed: %s\n", err_getstring(err));
            return err;
        }

        vaddr += bytes;
    }
    for (uint32_t *buf = (uint32_t *) base; (lvaddr_t) buf < vaddr; buf++)
        *buf = 0xAAAAAAAA;

    return SYS_ERR_OK;
}


static errval_t test_paging__simple(void)
{
    // We may not start from VADDR_OFFSET currenty, since the
    // slab_refill_pages() function claims virtual address space starting from
    // there.

    lvaddr_t vaddr = ((lvaddr_t) 512UL * 1024 * 1024 * 1024 * 16); // 16GB

    errval_t err;

    err = _test_paging_multiple(vaddr, &vaddr, 1, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "");
        return err;
    }

    err = _test_paging_multiple(vaddr, &vaddr, 1, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "");
        return err;
    }

    err = _test_paging_multiple(vaddr, &vaddr, 4, 4 * BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "");
        return err;
    }

    // For the next test to work, we need to fill the remaining L3 page
    // directory.
    err = _test_paging_multiple(vaddr, &vaddr, 462, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "");
        return err;
    }

    err = _test_paging_multiple(vaddr, &vaddr, 200, 512 * BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "");
        return err;
    }

    return SYS_ERR_OK;
}


__unused
static void paging_tests(void)
{
    errval_t err;

    debug_printf("testing map_arbitrary_addresses()\n");
    err = map_arbitrary_addresses();
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "");
    }

    debug_printf("testing test_paging__cause_errors()\n");
    err = test_paging__cause_errors();
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "");
    }

    debug_printf("testing test_paging__map_fixed_attr_with_gabs()\n");
    err = test_paging__map_fixed_attr_with_gabs();
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "");
    }

    debug_printf("testing test_paging__simple()\n");
    err = test_paging__simple();
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "");
    }

    printf("All tests successful\n");
}

int main(int argc, char *argv[])
{
    printf("Paging_tester\n");
    paging_tests();
    return EXIT_SUCCESS;
}
