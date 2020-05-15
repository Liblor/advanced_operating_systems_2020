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
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string";

__unused static void test_serial(void) {
    errval_t err;

    debug_printf("Testing serial RPC...\n");

    struct aos_rpc *rpc = aos_rpc_get_serial_channel();
    if (rpc == NULL) {
        debug_printf("Could not create serial channel\n");
        return;
    }
    /*
    // Explicit test not necessary since printf is redirected to rpc during thex
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

__unused
static void write_simple(void) {
    debug_printf("Testing write_simple ...\n");
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();
    if (rpc == NULL) {
        debug_printf("Could not create serial channel\n");
        return;
    }

    printf("%s\n", long_string);
    printf("If you see this message and the libc terminal write function is set in lib/aos/init.c it means aos_rpc_lmp_serial_putchar() is working\n");
    printf("1234567890abcdefghejklmnopqrstuvwxyz\n");

}


static int write_simple_th_func(void *args) {
    debug_printf("starting thread\n");
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();
    if (rpc == NULL) {
        debug_printf("Could not create serial channel\n");
        return 1;
    }

    printf("If you see this message and the libc terminal write function is set in lib/aos/init.c it means aos_rpc_lmp_serial_putchar() is working\n");

    return 0;
}

static void run_threads(size_t num_th, thread_func_t start_func, void *data)
{
    errval_t err;

    struct thread *threads[num_th];

    for (int i = 0; i < num_th; i++) {
        threads[i] = thread_create(start_func, data);
        assert(threads[i] != NULL);
    }

    for (int i = 0; i < num_th; i++) {
        int retval;
        err = thread_join(threads[i], &retval);
        assert(err_is_ok(err));
    }
}

// Threads dont work :(
__unused
static void write_simple_threads(void) {
    debug_printf("running threads\n");
    run_threads(2, write_simple_th_func, NULL);
}


int main(int argc, char *argv[])
{
    debug_printf("Running RPC tests...\n");

//     test_serial();
    write_simple();
    debug_printf("write_simple: ok\n");

    // write_simple_threads();

    debug_printf("done\n");

    return EXIT_SUCCESS;
}
