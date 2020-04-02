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

const char long_string[] = "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string\n";

__unused static void test_init(void) {
    errval_t err;

    debug_printf("Testing init RPC...\n");

    struct aos_rpc *rpc = aos_rpc_get_init_channel();
    if (rpc == NULL) {
        debug_printf("Could not create init channel\n");
        return;
    }

    err = aos_rpc_lmp_send_number(rpc, 13);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_send_number()");
        return;
    }

    err = aos_rpc_send_string(rpc, "1234567890abcdefghejklmnopqrstuvwxyz");
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_send_number()");
        return;
    }

    err = aos_rpc_send_string(rpc, long_string);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_send_number()");
        return;
    }
}

__unused static void test_memory(void) {
    // TODO
}

__unused static void test_process(void) {
    errval_t err;

    struct aos_rpc *rpc = aos_rpc_get_process_channel();
    const uint64_t process_number = 128;

    debug_printf("Testing aos_rpc_process_spawn() (spawning %u processes)...\n", process_number);
    for(int i = 0; i < process_number; i ++) {
        char *binary_name1 = "dummy";
        domainid_t pid1;
        coreid_t core = 0;

        err = aos_rpc_process_spawn(rpc, binary_name1, core, &pid1);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "aos_rpc_process_spawn()");
            return;
        }

        debug_printf("spawned child: pid %d\n", pid1);
    }

    debug_printf("Testing aos_rpc_lmp_process_get_name()...\n");
    for(int i = 0; i < process_number; i ++) {
        char *name = NULL;

        err = aos_rpc_lmp_process_get_name(rpc, i, &name);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "aos_rpc_lmp_process_get_name()\n");
            return;
        }

        debug_printf("aos_rpc_lmp_process_get_name: %s\n", name);
    }

    debug_printf("Testing aos_rpc_lmp_process_get_all_pids()...\n");
    domainid_t *pids = NULL;
    size_t pid_count = -1;
    err = aos_rpc_lmp_process_get_all_pids(rpc, &pids, &pid_count);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_process_get_all_pids()\n");
        return;
    }
    //debug_printf("aos_rpc_lmp_process_get_all_pids:\n");
    //for(int j = 0; j < pid_count; j ++){
        //debug_printf("pid: %d:\n", pids[j]);
    //}
}

__unused static void test_serial(void) {
    errval_t err;

    debug_printf("Testing serial RPC...\n");

    struct aos_rpc *rpc = aos_rpc_get_serial_channel();
    if (rpc == NULL) {
        debug_printf("Could not create serial channel\n");
        return;
    }

    /*
    // Explicit test not necessary since printf is redirected to rpc during the
    // execution of this entire program.
    err = aos_rpc_lmp_serial_putchar(rpc_serial, 'a');
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_serial_putchar()");
        return;
    }
    */

    printf("If you see this message and the libc terminal write function is set in lib/aos/init.c it means aos_rpc_lmp_serial_putchar() is working\n");
    printf("1234567890abcdefghejklmnopqrstuvwxyz\n");

    debug_printf("Press a button to test aos_rpc_lmp_serial_getchar(): ");
    char c;
    err = aos_rpc_lmp_serial_getchar(rpc, &c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_serial_getchar()");
        return;
    }
    debug_printf("\n");
    debug_printf("Received %c\n", c);
}

int main(int argc, char *argv[])
{
    debug_printf("Running RPC tests...\n");

    //test_init();
    //test_memory();
    test_process();
    //test_serial();

    return EXIT_SUCCESS;
}
