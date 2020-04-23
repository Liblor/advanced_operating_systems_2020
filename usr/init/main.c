/**
 * \file
 * \brief init process for child spawning
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <aos/urpc.h>
#include <aos/capabilities.h>
#include <mm/mm.h>
#include <spawn/spawn.h>
#include <grading.h>
#include <aos/coreboot.h>
#include <aos/kernel_cap_invocations.h>

#include "mem_alloc.h"
#include "initserver.h"
#include "memoryserver.h"
#include "serialserver.h"
#include "processserver.h"
#include "test.h"
#include "aos/urpc.h"

struct bootinfo *bi;

coreid_t my_core_id;

static void number_cb(uintptr_t num)
{
    grading_rpc_handle_number(num);
}

static void string_cb(char *c)
{
    grading_rpc_handler_string(c);
}

// We do not allocate RAM here. This should be done in the server itself.
static errval_t ram_cap_cb(const size_t bytes, const size_t alignment, struct capref *retcap, size_t *retbytes)
{
    errval_t err;

    grading_rpc_handler_ram_cap(bytes, alignment);

    err = ram_alloc_aligned(retcap, bytes, alignment);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "ram_alloc_aligned() failed");
        return err_push(err, LIB_ERR_RAM_ALLOC);
    }

    struct capability cap;
    err = cap_direct_identify(*retcap, &cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "cap_direct_identify() failed");
        return err_push(err, LIB_ERR_CAP_IDENTIFY);
    }

    *retbytes = get_size(&cap);

    return SYS_ERR_OK;
}

static void putchar_cb(char c) {
    errval_t err;

    grading_rpc_handler_serial_putchar(c);

    err = sys_print((const char *)&c, 1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sys_print() failed");
    }
}

static void getchar_cb(char *c) {
    errval_t err;

    grading_rpc_handler_serial_getchar();

    err = sys_getchar(c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sys_getchar() failed");
    }
}

static errval_t spawn_cb(struct processserver_state *processserver_state, char *name, coreid_t coreid, domainid_t *ret_pid)
{
    errval_t err;

    grading_rpc_handler_process_spawn(name, coreid);

    struct spawninfo si;

    // TODO: Also store coreid
    err = add_to_proc_list(processserver_state, name, ret_pid);

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "add_to_proc_list()");
        return err;
    }

    // XXX: we currently use add_to_proc_list to get a ret_pid
    // and ignore the ret_pid set by urpc_send_spawn_request or spawn_load_by_name
    // reason: legacy, spawn_load_by_name does not set pid itself, so
    // add_to_proc_list implemented the behavior

    if (coreid == disp_get_core_id()) {
        err = spawn_load_by_name(name, &si, ret_pid);
    } else {
        domainid_t pid;
        err = urpc_send_spawn_request(name, coreid, &pid);
    }

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "spawn_load_by_name()");
        // TODO: If spawn failed, remove the process from the processserver state list.
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t get_name_cb(struct processserver_state *processserver_state, domainid_t pid, char **ret_name) {
    errval_t err;

    grading_rpc_handler_process_get_name(pid);

    err = get_name_by_pid(processserver_state, pid, ret_name);

    return err;
}

static errval_t process_get_all_pids(struct processserver_state *processserver_state, size_t *ret_count, domainid_t **ret_pids) {
    errval_t err;

    grading_rpc_handler_process_get_all_pids();

    err = get_all_pids(processserver_state, ret_count, ret_pids);

    return err;
}

static int bsp_main(int argc, char *argv[])
{
    errval_t err;

    // Grading
    grading_setup_bsp_init(argc, argv);

    // First argument contains the bootinfo location, if it's not set
    bi = (struct bootinfo*)strtol(argv[1], NULL, 10);
    assert(bi);

    err = initialize_ram_alloc(2);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "initialize_ram_alloc");
    }

    // Grading
    grading_test_early();

    err = initserver_init(number_cb, string_cb);
    if (err_is_fail(err)) {
        debug_printf("initserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    err = memoryserver_init(ram_cap_cb);
    if (err_is_fail(err)) {
        debug_printf("memoryserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    err = serialserver_init(putchar_cb, getchar_cb);
    if (err_is_fail(err)) {
        debug_printf("serialserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    err = processserver_init(spawn_cb, get_name_cb, process_get_all_pids);
    if (err_is_fail(err)) {
        debug_printf("processserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    // TODO: Discuss about aos_rpc_init, as it is unused
    err = master_urpc_init();
    if (err_is_fail(err)) {
        debug_printf("master_urpc_init failed: %s\n", err_getstring(err));
        abort();
    }

    struct frame_identity urpc_frame_id;
    err = frame_identify(cap_urpc, &urpc_frame_id);
    if (err_is_fail(err)) {
        debug_printf("frame identity for urpc failed: %s\n", err_getstring(err));
        abort();
    }
    err = coreboot(1, "boot_armv8_generic", "cpu_imx8x", "init", urpc_frame_id);
    if (err_is_fail(err)) {
        debug_printf("coreboot failed: %s\n", err_getstring(err));
        abort();
    }

    err = urpc_send_boot_info(bi);
    if (err_is_fail(err)) {
        debug_printf("urpc_send_boot_info failed: %s\n", err_getstring(err));
        abort();
    }

    // Grading
    grading_test_late();

    {
        domainid_t pid;
        struct spawninfo si;
        err = spawn_load_by_name("multicore_test", &si, &pid);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "spawn_load_by_name failed");
            abort();
        }
    }

    debug_printf("Message handler loop\n");

    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }
    return EXIT_SUCCESS;
}

static errval_t app_urpc_slave_spawn(char *cmdline, domainid_t *ret_pid)
{
    errval_t err;

    struct spawninfo si;

    err = spawn_load_by_name(cmdline, &si, ret_pid);

    if (err_is_fail(err)) {
        debug_printf("error in app_urpc_slave_spawn, cannot spawn %s: %s\n",
                cmdline, err_getstring(err));
        return err;
    }
    return SYS_ERR_OK;
}

static int app_main(int argc, char *argv[])
{
    // TODO
    // Implement me in Milestone 5
    // Remember to call
    // - grading_setup_app_init(..);
    // - grading_test_early();
    // - grading_test_late();

    errval_t err;
    debug_printf("hello world from app_main\n");

    grading_test_early();

    // TODO: Decide which servers do we really need?
    err = initserver_init(number_cb, string_cb);
    if (err_is_fail(err)) {
        debug_printf("initserver_init() failed: %s\n", err_getstring(err));
        abort();
    }
    err = memoryserver_init(ram_cap_cb);
    if (err_is_fail(err)) {
        debug_printf("memoryserver_init() failed: %s\n", err_getstring(err));
        abort();
    }
    err = serialserver_init(putchar_cb, getchar_cb);
    if (err_is_fail(err)) {
        debug_printf("serialserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    err = processserver_init(spawn_cb, get_name_cb, process_get_all_pids);
    if (err_is_fail(err)) {
        debug_printf("processserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    urpc_slave_spawn_process = app_urpc_slave_spawn;

    err = urpc_slave_init();
    if (err_is_fail(err)) {
        debug_printf("failure in urpc_init: %s", err_getstring(err));
        return err;
    }
    genpaddr_t mmstrings_base;
    gensize_t mmstrings_size;

    err = urpc_receive_bootinfo(&bi, &mmstrings_base, &mmstrings_size);
    if (err_is_fail(err)) {
        debug_printf("failure in urpc_receive_bootinfo: %s", err_getstring(err));
        return err;
    }

    grading_setup_app_init(bi);

    err = forge_bootinfo_ram(bi);
    if (err_is_fail(err)) {
        debug_printf("forging ram failed: %s\n", err_getstring(err));
        return err;
    }

    err = initialize_ram_alloc(2);
    if (err_is_fail(err)) {
        debug_printf("initialize_ram_alloc failed: %s\n", err_getstring(err));
        return err;
    }
    err = forge_bootinfo_capabilities(bi, mmstrings_base, mmstrings_size);
    if (err_is_fail(err)) {
        debug_printf("forging capabilities failed: %s\n", err_getstring(err));
        return err;
    }

    grading_test_late();

    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = urpc_slave_serve_non_block();
        if (err != LIB_ERR_NO_EVENT && err_is_fail(err)) {
            debug_printf("urpc_slave_serve_req failed: %s\n ", err_getstring(err));
            abort();
        }

        err = event_dispatch_non_block(default_ws);
        if (err != LIB_ERR_NO_EVENT &&  err_is_fail(err)) {
            DEBUG_ERR(err, "err in event_dispatch");
            abort();
        }
    }

    return SYS_ERR_OK;
}

int main(int argc, char *argv[])
{
    errval_t err;

    /* Set the core id in the disp_priv struct */
    err = invoke_kernel_get_core_id(cap_kernel, &my_core_id);
    assert(err_is_ok(err));
    disp_set_core_id(my_core_id);

    debug_printf("init: on core %" PRIuCOREID ", invoked as:", my_core_id);
    for (int i = 0; i < argc; i++) {
       printf(" %s", argv[i]);
    }
    printf("\n");
    fflush(stdout);

    if(my_core_id == 0) return bsp_main(argc, argv);
    else                return app_main(argc, argv);
}
