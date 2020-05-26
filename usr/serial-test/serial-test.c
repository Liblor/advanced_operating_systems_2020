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
#include <arch/aarch64/aos/dispatcher_arch.h>

const char long_string[] = "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string";

__unused static void test_serial(void)
{
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
static void write_simple(void)
{
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

__unused
static int write_simple_th_func(void *args)
{
    debug_printf("starting thread\n");
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();
    if (rpc == NULL) {
        debug_printf("Could not create serial channel\n");
        return 1;
    }

    printf("If you see this message and the libc terminal write function is set in lib/aos/init.c it means aos_rpc_lmp_serial_putchar() is working\n");

    return 0;
}

__unused
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
static void write_simple_threads(void)
{
    debug_printf("running threads\n");
    run_threads(2, write_simple_th_func, NULL);
}

__unused
static void read_loop(void)
{
    errval_t err;
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();

    const size_t buf_size = 2048;
    char buf[2048];
    memset(&buf, 0, buf_size);
    printf("Write something and hit return\r\n");

    int i = 0;
    do {
        char c;
        err = aos_rpc_lmp_serial_getchar(rpc, &c);
        if (IS_CHAR_LINEBREAK(c)) {
            buf[i] = 0;
            printf("\r\n");
            printf("You typed: '%s' \r\n", &buf);
            fflush(stdout);
            i = 0;
        } else {
            buf[i] = c;
            fflush(stdout);
            printf("%c", c);
            fflush(stdout);
            i++;
            if (i == buf_size) {
                i = 0;
            }
        }
    } while (err_is_ok(err));

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_serial_getchar()");
        return;
    }
    debug_printf("\n");
}

__unused
static void printf_test(void)
{
    errval_t err;
    char c;
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();
    err = aos_rpc_lmp_serial_getchar(rpc, &c);
    printf("test 2\n");

    err = aos_rpc_lmp_serial_getchar(rpc, &c);


    char buf2[1024];
    memset(&buf2, 0, sizeof(buf2));


    char buf[] = "hello there";
    printf("%s", buf);


    for (int i = 0; i < 10; i++) {
        err = aos_rpc_lmp_serial_getchar(rpc, &c);
        printf("%c", c);
        fflush(stdout); // must be flushed explicitly, took a while to debug
    }
}

__unused
static void spawn_serial_tests(void) {
    struct aos_rpc *rpc = aos_rpc_get_process_channel();
    domainid_t pid;

    aos_rpc_process_spawn(rpc, "serial-read-test", 0, &pid);
    // aos_rpc_process_spawn(rpc, "serial-read-test", 0, &pid);
}


__unused
int main(int argc, char *argv[])
{

    struct dispatcher_generic *disp = get_dispatcher_generic(curdispatcher());
    __unused domainid_t my_pid = disp->domain_id;
    __unused coreid_t my_core = disp->core_id;


//    printf("argc: %d\n", argc);
#if 1
    errval_t err = SYS_ERR_OK;
    if (argc == 1) {
//        printf("Running serial-tests...\n");
        struct aos_rpc *rpc = aos_rpc_get_process_channel();
        domainid_t pid;
        err = aos_rpc_process_spawn(rpc, "serial-test 1", 1, &pid);
        assert(err_is_ok(err));
        printf("Spawning child with pid %d\n", pid);
//
        err = aos_rpc_process_spawn(rpc, "serial-test 1", 0, &pid);
        assert(err_is_ok(err));
        printf("Spawning child with pid %d\n", pid);

        err = aos_rpc_process_spawn(rpc, "serial-test 1", 1, &pid);
        assert(err_is_ok(err));
        printf("Spawning child with pid %d\n", pid);

        err = aos_rpc_process_spawn(rpc, "serial-test 1", 1, &pid);
        assert(err_is_ok(err));
        printf("Spawning child with pid %d\n", pid);
        return SYS_ERR_OK;
    } else {
//        printf("done\n");
//        debug_printf("done\n");
        struct aos_rpc *rpc = aos_rpc_get_serial_channel();
        char c;
        err = aos_rpc_lmp_serial_getchar(rpc, &c);
        assert(err_is_ok(err));
        debug_printf("you typed: %c in pid:%d on core %d\n", c, my_pid, my_core);
    }
#endif
    return EXIT_SUCCESS;
}
