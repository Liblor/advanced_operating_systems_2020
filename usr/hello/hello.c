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

static void test_serial_channel(void) {
    struct aos_rpc *rpc_serial = aos_rpc_get_serial_channel();
    errval_t err;
    if (rpc_serial == NULL) {
        debug_printf("Could not create serial channel\n");
        USER_PANIC("");
    }

    // Explicit test not necessary since printf is redirected to rpc during the
    // execution of this entire program.
//    err = aos_rpc_lmp_serial_putchar(rpc_serial, 'a');
//    if (err_is_fail(err)) {
//        DEBUG_ERR(err, "aos_rpc_lmp_serial_putchar()");
//        USER_PANIC_ERR(err, "");
//    }


    char c;
    err = aos_rpc_lmp_serial_getchar(rpc_serial, &c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_serial_getchar()");
        USER_PANIC("");
    }
    debug_printf("Received %c\n", c);
}

__unused static bool test_rpc(void)
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

    err = aos_rpc_send_string(rpc, "hello world hello world whhhhhhhhh");
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_send_number()");
        return false;
    }


    debug_printf("calling aos_rpc_process_spawn\n");
    rpc = aos_rpc_get_process_channel();

    {
        for(int i = 0; i < 10; i ++) {
            char *binary_name1 = "dummy";
            domainid_t pid1;
            coreid_t core = 0;

            err = aos_rpc_process_spawn(rpc, binary_name1, core, &pid1);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "aos_rpc_process_spawn()");
                return false;
            }
            debug_printf("spawned child: pid %d\n", pid1);
        }
    }
    {
        for(int i = 0; i < 10; i ++) {
            char *name = NULL;
            err = aos_rpc_lmp_process_get_name(rpc, i, &name);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "aos_rpc_lmp_process_get_name()\n");
                return false;
            }
            debug_printf("aos_rpc_lmp_process_get_name: %s\n", name);
        }
    }
    {
        domainid_t *pids = NULL;
        size_t pid_count = -1;
        err = aos_rpc_lmp_process_get_all_pids(rpc, &pids, &pid_count);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "aos_rpc_lmp_process_get_all_pids()\n");
            return false;
        }
        debug_printf("aos_rpc_lmp_process_get_all_pids:\n");
        for(int j = 0; j < pid_count; j ++){
            debug_printf("pid: %d:\n", pids[j]);
        }
    }

    return true;
}

int main(int argc, char *argv[])
{
    printf("Hello, world! from userspace\n");

    for (int i = 0; i < argc; i++) {
        printf("argv[%d]='%s'\n", i, argv[i]);
    }


    test_serial_channel();

//    bool success;
//    success = test_rpc();
//    if (!success) {
//        return EXIT_FAILURE;
//    }
    debug_printf("done...\n");
    return EXIT_SUCCESS;
}
