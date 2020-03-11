/*
 * Created by Loris
 * Basic tests of mm
 */

#include "tests.h"
#include "mem_alloc.h"


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

__attribute__((unused)) void test_aligned_alloc(void) {
    debug_printf("[test_aligned_alloc] start\n");
    struct capref caps[4];

    errval_t err = aos_ram_alloc_aligned(&(caps[0]), BASE_PAGE_SIZE, BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }

    err = aos_ram_alloc_aligned(&(caps[1]), BASE_PAGE_SIZE, 2*BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }

    err = aos_ram_alloc_aligned(&(caps[2]), BASE_PAGE_SIZE, BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }

    err = aos_ram_alloc_aligned(&(caps[3]), 2*BASE_PAGE_SIZE, 2*BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }

    err = aos_ram_free(cap[2], BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }

    err = aos_ram_free(cap[1], BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }

    err = aos_ram_free(cap[3], BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }

    err = aos_ram_free(cap[0], BASE_PAGE_SIZE);
    if (err_is_fail(err)) { err_print_calltrace(err); return; }

    debug_printf("[test_aligned_alloc] end\n");
}
