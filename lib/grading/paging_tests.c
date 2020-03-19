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
