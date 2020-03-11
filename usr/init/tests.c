/*
 * Created by Loris
 * Basic tests of mm
 */

#include "tests.h"
#include "mem_alloc.h"


/**
 * Verify that the allocator handles 256 requests and that the slot
 * allocator works
 */
__attribute__((unused)) void test_alloc_free_x256(void) {
    debug_printf("[test_alloc_free_x256] start\n");
    struct capref caps[256];
    for (int i = 0; i < 256; i++) {
        errval_t err = aos_ram_alloc_aligned(&(caps[i]), BASE_PAGE_SIZE, BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            err_print_calltrace(err);
            return;
        }
    }
    for (int i = 0; i < 256; i++) {
        errval_t err = aos_ram_free(caps[i], BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            debug_printf("iter: %i\n", i);
            err_print_calltrace(err);
            return;
        }
    }
    debug_printf("[test_alloc_free_x256] end\n");
}

/**
 * Manual verification that aligned allocs work and that the frees merge correctly
 */
__attribute__((unused)) void test_aligned_alloc1(void) {
    debug_printf("[test_aligned_alloc1] start\n");
    struct capref caps[4];

    errval_t err = aos_ram_alloc_aligned(&(caps[0]), BASE_PAGE_SIZE, BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    err = aos_ram_alloc_aligned(&(caps[1]), BASE_PAGE_SIZE, 8*BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    err = aos_ram_alloc_aligned(&(caps[2]), BASE_PAGE_SIZE, BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    err = aos_ram_alloc_aligned(&(caps[3]), 2*BASE_PAGE_SIZE, 2*BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    err = aos_ram_free(caps[2], BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    err = aos_ram_free(caps[1], BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    err = aos_ram_free(caps[3], 2*BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    err = aos_ram_free(caps[0], BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    debug_printf("[test_aligned_alloc1] end\n");
}

/**
 * Manual verification that aligned allocs work and that the frees merge correctly
 */
__attribute__((unused)) void test_aligned_alloc2(void) {
    debug_printf("[test_aligned_alloc2] start\n");
    struct capref caps[3];

    errval_t err = aos_ram_alloc_aligned(&(caps[0]), 2*BASE_PAGE_SIZE, 2*BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    err = aos_ram_alloc_aligned(&(caps[1]), 2*BASE_PAGE_SIZE, 2*BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    // free
    err = aos_ram_free(caps[0], BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    err = aos_ram_alloc_aligned(&(caps[0]), BASE_PAGE_SIZE, BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    err = aos_ram_alloc_aligned(&(caps[2]), 8*BASE_PAGE_SIZE, 2*BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    // free
    err = aos_ram_free(caps[1], BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    // free
    err = aos_ram_free(caps[2], BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    // free
    err = aos_ram_free(caps[0], BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }
    print_mm_linked_list();

    debug_printf("[test_aligned_alloc2] end\n");
}

__attribute__((unused)) void test_map_page_get_frame(void) {
    errval_t err;
    struct capref frame_cap;
    gensize_t bytes = BASE_PAGE_SIZE;

    debug_printf("Allocate frame\n");
    err = frame_alloc(&frame_cap, bytes, &bytes);
    if (err_is_fail(err)) { err_print_calltrace(err_push(err, LIB_ERR_FRAME_CREATE)); return; }

    void *buf;
    debug_printf("Map page\n");
    lvaddr_t addr = get_current_paging_state()->last_addr;
    err = paging_map_fixed_attr(get_current_paging_state(), addr, frame_cap, bytes, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) { err_print_calltrace(err_push(err, LIB_ERR_VSPACE_MAP)); return; }
    get_current_paging_state()->last_addr += bytes;

    buf = (void *)addr;
    debug_printf("Write \"hello world\" to new page\n");
    strcpy((char *)buf, "hello world");
    debug_printf("Read from it: %s\n", buf);
}

__attribute__((unused)) void test_mapping_pages(void) {
    struct capref frame_cap;
    gensize_t bytes = BASE_PAGE_SIZE;

    // Currently not more than 128 pages are supported, due to
    // the standard slot allocator being used
    for (int i = 0; i < 20; i++) {
        errval_t err = frame_alloc(&frame_cap, bytes, &bytes);
        if (err_is_fail(err)) { err_print_calltrace(err_push(err, LIB_ERR_FRAME_CREATE)); return; }

        lvaddr_t addr = get_current_paging_state()->last_addr;
        err = paging_map_fixed_attr(get_current_paging_state(), addr, frame_cap, bytes, VREGION_FLAGS_READ_WRITE);
        if (err_is_fail(err)) { err_print_calltrace(err_push(err, LIB_ERR_VSPACE_MAP)); return; }
        get_current_paging_state()->last_addr += bytes;
    }
}
