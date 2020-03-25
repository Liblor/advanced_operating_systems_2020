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

static bool test_rpc(void)
{
    errval_t err;

    struct aos_rpc *rpc = aos_rpc_get_init_channel();
    if (rpc == NULL) {
        debug_printf("Could not create init channel\n");
        return false;
    }

    err = aos_rpc_lmp_send_number(rpc, 2);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_send_number()");
        return false;
    }

    return true;
}

int main(int argc, char *argv[])
{
    printf("Hello, world! from userspace\n");

    for (int i = 0; i < argc; i++) {
        printf("argv[%d]='%s'\n", i, argv[i]);
    }

    bool success;

    success = test_rpc();
    if (!success) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
