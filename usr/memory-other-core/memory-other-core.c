/**
 * \file
 * \brief Hello world application
 */

/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#include <stdio.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>

int main(int argc, char *argv[])
{
    debug_printf("Hello, world! from userspace\n");

    // XXX: spawn this on core 1 as memory server runs on core 0

    struct capref ram;
    size_t ret_bytes;

    errval_t err = aos_rpc_get_remote_ram_cap(
            BASE_PAGE_SIZE,
            BASE_PAGE_SIZE,
            (disp_get_core_id() + 1) % 2,
            &ram,
            &ret_bytes
    );

    assert(err_is_ok(err));

    struct capref frame;
    err = slot_alloc(&frame);
    assert(err_is_ok(err));

    err = cap_retype(frame, ram, 0, ObjType_Frame, ret_bytes, 1);
    assert(err_is_ok(err));

    char *addr;
    err = paging_map_frame(get_current_paging_state(), (void **) &addr, ret_bytes, frame, 0, 0);
    assert(err_is_ok(err));

    for (int i = 0; i < ret_bytes; i++) {
        *(addr + i) = 0;
    }


    debug_printf("memory-other-core successfull\n");
    return EXIT_SUCCESS;
}
