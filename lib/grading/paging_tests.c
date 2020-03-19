#include <aos/paging.h>
#include <aos/domain.h>
#include "minunit.h"
#include "paging_tests.h"


MU_TEST_SUITE(test_suite) {
    MU_SUITE_CONFIGURE(&test_setup, &test_teardown);

    MU_RUN_TEST(map_arbitrary_addresses);
}

static void test_setup(void) {
}

static void test_teardown(void) {
}

void run_paging_tests(void) {
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
}


static inline void create_map_write_frame(lvaddr_t vaddr, size_t bytes) {
    struct capref frame;
    char *buf1 = (char *)vaddr;
    errval_t err = frame_alloc(&frame, bytes, &bytes);
    mu_assert(err_is_ok(err), "frame alloc shouldn't have failed\n");
    err = paging_map_fixed_attr(get_current_paging_state(), (lvaddr_t)buf1, frame,
                                bytes, VREGION_FLAGS_READ_WRITE);
    mu_assert(err_is_ok(err), "paging_map_fixed failed\n");

    for (int i = 0; i < bytes; i++) {
        buf1[i] = 0xff;
    }
}


MU_TEST(map_arbitrary_addresses) {
    create_map_write_frame(0xFFFF00000000, 4*BASE_PAGE_SIZE);
    create_map_write_frame(0xEFFF00000000, 2*BASE_PAGE_SIZE);
    create_map_write_frame(0xEFF305500000, BASE_PAGE_SIZE);
    create_map_write_frame(0xE1F305500000, 64*BASE_PAGE_SIZE);
}
