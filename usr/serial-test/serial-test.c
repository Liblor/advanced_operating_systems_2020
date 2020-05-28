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
#include <aos/deferred.h>


#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>


const char long_string[] = "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string"
                           "this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string this is a very long string\n";

static char *colors[100];
static int colors_len;


static int my_pid = 0;
static int my_core = 0;
static int my_color;

#define PRINTF_COLORS(format, ...) printf("%s[pid: %d] " format COLOR_RESET, colors[my_color], my_pid, ## __VA_ARGS__)

__unused
static void write_simple(void)
{
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();
    if (rpc == NULL) {
        PRINTF_COLORS("Could not create serial channel\n");
        return;
    }

    PRINTF_COLORS("%s\n", long_string);
    PRINTF_COLORS(
            "If you see this message and the libc terminal write function is set in lib/aos/init.c it means aos_rpc_lmp_serial_putchar() is working\n");
    PRINTF_COLORS("1234567890abcdefghejklmnopqrstuvwxyz\n");

    for (int i = 0; i < 3; i++) {
        PRINTF_COLORS("i: %d, '%s'\n", i, long_string);
    }
}

__unused
static void read_loop(void)
{
    errval_t err;
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();

    const size_t buf_size = 100;
    char buf[100];
    memset(&buf, 0, buf_size);

    PRINTF_COLORS("Write something and hit return\n");
    // write_simple();

    int i = 0;
    do {
        char c;
        err = aos_rpc_lmp_serial_getchar(rpc, &c);
        if (IS_CHAR_LINEBREAK(c)) {
            buf[i] = 0;
            PRINTF_COLORS("typed: '%s'. exiting now... \n", buf);
            return;
        } else {
            buf[i] = c;
            PRINTF_COLORS(" %c\n", c);
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
}

static errval_t wait_until_exit(const domainid_t pids[], size_t len)
{
    if (len == 0) return SYS_ERR_OK;

    errval_t err = SYS_ERR_OK;
    bool dead;
    struct aos_rpc *rpc = aos_rpc_get_process_channel();
    do {
        dead = true;
        for (size_t i = 0; i < len;  i++) {
            domainid_t pid = pids[i];
            struct aos_rpc_process_info_reply *reply = NULL;
            err = aos_rpc_lmp_process_get_info(rpc, pid, &reply);
            if (err_is_fail(err)) {
                free(reply);
                return err;
            }
            if (reply->status != ProcessStatus_Exit) {
                dead = false;
            }
            free(reply);
            barrelfish_usleep(500);
            event_dispatch_non_block(get_default_waitset());
        }
    } while (!dead);

    return err;
}

__unused
int main(int argc, char *argv[])
{

    colors[0] = COLOR_RED;
    colors[1] = COLOR_GRN;
    colors[2] = COLOR_YEL;
    colors[3] = COLOR_BLU;
    colors[4] = COLOR_MAG;
    colors[5] = COLOR_CYN;
    colors_len = 6;

    struct dispatcher_generic *disp = get_dispatcher_generic(curdispatcher());
    my_pid = disp->domain_id;
    my_core = disp->core_id;
    my_color = my_pid % colors_len;


#if 1
    errval_t err = SYS_ERR_OK;
    if (argc == 1) {

        PRINTF_COLORS(
                "You may want to run this with oncore -f flag such that shell is suspended\n");

        PRINTF_COLORS("This test demonstrates how serial getchar is demultiplexed among domains\n");
        PRINTF_COLORS("spawning children...\n");

        domainid_t pids[100];
        int i = 0;
        struct aos_rpc *rpc = aos_rpc_get_process_channel();
        domainid_t pid;

        err = aos_rpc_process_spawn(rpc, "serial-test 1", 0, &pid);
        assert(err_is_ok(err));
        PRINTF_COLORS("Spawning child with pid %d\n", pid);
        pids[i] = pid;
        i ++;


        err = aos_rpc_process_spawn(rpc, "serial-test 1", 0, &pid);
        assert(err_is_ok(err));
        PRINTF_COLORS("Spawning child with pid %d\n", pid);
        pids[i] = pid;
        i ++;


        err = aos_rpc_process_spawn(rpc, "serial-test 1", 0, &pid);
        assert(err_is_ok(err));
        PRINTF_COLORS("Spawning child with pid %d\n", pid);
        pids[i] = pid;
        i ++;


        err = aos_rpc_process_spawn(rpc, "serial-test 1", 0, &pid);
        assert(err_is_ok(err));
        PRINTF_COLORS("Spawning child with pid %d\n", pid);
        pids[i] = pid;
        i ++;


        PRINTF_COLORS("Waiting until children have exited\n");

        wait_until_exit(pids, i);
        PRINTF_COLORS("All pids exited\n");

        return SYS_ERR_OK;
    } else {
        read_loop();
    }
#endif
    return EXIT_SUCCESS;
}
