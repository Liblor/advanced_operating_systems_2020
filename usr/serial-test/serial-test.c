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
static
void test_putstr(void)
{
    __unused
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();
    debug_printf("rpc : %p\n", rpc);
    errval_t err = aos_rpc_serial_putchar(rpc, '7');

    printf("1234567890abcdefghejklmnopqrstuvwxyz" ENDL);
    printf("1234567890abcdefghejklmnopqrstuvwxyz" ENDL);

    int i = 0;
    while (i < 100) {
        printf("%d" ENDL, i);
        i++;
    }

    assert(err_is_ok(err));
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
        thread_yield();
    } while (err_is_ok(err));

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_serial_getchar()");
        return;
    }
    debug_printf("\n");
}

__unused
static
void test_getchar(void)
{
//    read_loop();

    errval_t err;
    char c;
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();
    printf("type a char:" ENDL);
    err = aos_rpc_lmp_serial_getchar(rpc, &c);
    assert(err_is_ok(err));
    printf("->: %c" ENDL, c);
    debug_printf("done\n");
}

__unused
int main(int argc, char *argv[])
{
    debug_printf("Running serial tests...\n");
//    test_putstr();
    test_getchar();

    debug_printf("hanging around\n");
    while (true) {
        event_dispatch(get_default_waitset());
    }
    return EXIT_SUCCESS;
}
