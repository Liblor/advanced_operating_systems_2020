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
#include <aos/debug.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <aos/string.h>

__unused
int main(int argc, char *argv[])
{

    debug_printf("Running serial tests...\n");

    __unused
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();
    debug_printf("rpc : %p\n", rpc);
    errval_t err = aos_rpc_serial_putchar(rpc, '7');

    printf("1234567890abcdefghejklmnopqrstuvwxyz" ENDL);
    printf("1234567890abcdefghejklmnopqrstuvwxyz" ENDL);

    int i = 0;
    while(i < 100) {
        printf("%d" ENDL, i);
        i++;
    }

    assert(err_is_ok(err));

    debug_printf("done\n");

    return EXIT_SUCCESS;
}
