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
#include <aos/aos_rpc_ump.h>

#include "mem_alloc.h"
#include "initserver.h"
#include "memoryserver.h"
#include "serialserver.h"
#include "processserver.h"
#include "test.h"
#include "aos/urpc.h"
#include "monitorserver.h"

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

static void setup_servers(
        void
)
{
    errval_t err;

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

    err = monitorserver_init();
    if (err_is_fail(err)) {
        debug_printf("monitorserver_init() failed: %s\n", err_getstring(err));
        abort();
    }
}

static void setup_core(
        struct bootinfo *bootinfo,
        coreid_t mpid
)
{
    errval_t err;
    struct capref frame;

    err = frame_alloc(&frame, UMP_SHARED_FRAME_SIZE, NULL);
    if (err_is_fail(err)) {
        debug_printf("frame_alloc() failed: %s\n", err_getstring(err));
        abort();
    }

    struct aos_rpc rpc;

    err = aos_rpc_ump_init(&rpc, frame, true);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_init() failed: %s\n", err_getstring(err));
        abort();
    }

    struct frame_identity frame_id;
    err = frame_identify(frame, &frame_id);
    if (err_is_fail(err)) {
        debug_printf("frame_identify() failed: %s\n", err_getstring(err));
        abort();
    }

    err = coreboot(mpid, "boot_armv8_generic", "cpu_imx8x", "init", frame_id);
    if (err_is_fail(err)) {
        debug_printf("coreboot() failed: %s\n", err_getstring(err));
        abort();
    }

    const size_t size = sizeof(struct bootinfo) + bootinfo->regions_length * sizeof(struct mem_region);
    char buffer[sizeof(struct rpc_message) + size];
    memset(buffer, 0x00, sizeof(buffer));

    struct rpc_message *rpc_message = (struct rpc_message *) buffer;
    rpc_message->msg.payload_length = size;
    rpc_message->msg.status = Status_Ok;
    rpc_message->msg.method = Method_Send_Bootinfo;
    rpc_message->cap = cap_mmstrings;
    memcpy(rpc_message->msg.payload, bootinfo, size);

    err = aos_rpc_ump_send_message(&rpc, rpc_message);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_send_message() failed: %s\n", err_getstring(err));
        abort();
    }
}

static int first_main(int argc, char *argv[])
{
    errval_t err;

    // Grading
    grading_setup_bsp_init(argc, argv);

    // First argument contains the bootinfo location, if it's not set
    bi = (struct bootinfo*) strtol(argv[1], NULL, 10);
    assert(bi != NULL);

    err = initialize_ram_alloc(2);
    if(err_is_fail(err)){
        debug_printf("initialize_ram_alloc() failed: %s\n", err_getstring(err));
        abort();
    }

    // Grading
    grading_test_early();

    setup_servers();

    setup_core(bi, 1);

#if 0
    domainid_t pid;
    struct spawninfo si;
    err = spawn_load_by_name("hello", &si, &pid);
    if (err_is_fail(err)) {
        debug_printf("spawn_load_by_name() failed: %s\n", err_getstring(err));
        abort();
    }
#endif

    // Grading
    grading_test_late();

    debug_printf("Entering message handler loop...\n");

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

static void receive_bootinfo(
        struct aos_rpc *rpc,
        struct bootinfo **bootinfo,
        struct capref *cap
)
{
    errval_t err;

    struct rpc_message *rpc_message = NULL;

    err = aos_rpc_ump_receive(rpc, &rpc_message);
    assert(err_is_ok(err));

    assert(rpc_message != NULL);
    assert(rpc_message->msg.payload_length >= sizeof(struct bootinfo));
    assert(rpc_message->msg.status == Status_Ok);
    assert(rpc_message->msg.method == Method_Send_Bootinfo);
    debug_printf("Receiving bootinfo successful!\n");

    *bootinfo = malloc(rpc_message->msg.payload_length);
    memcpy(*bootinfo, rpc_message->msg.payload, rpc_message->msg.payload_length);

    *cap = rpc_message->cap;
}

static int other_main(int argc, char *argv[])
{
    errval_t err;

    // Grading
    grading_setup_bsp_init(argc, argv);

    struct aos_rpc rpc;

    err = aos_rpc_ump_init(&rpc, cap_urpc, false);
    assert(err_is_ok(err));

    struct capref cap_mmstrings_frame;
    receive_bootinfo(&rpc, &bi, &cap_mmstrings_frame);

    err = forge_bootinfo_ram(bi);
    if (err_is_fail(err)) {
        debug_printf("forge_bootinfo_ram() failed: %s\n", err_getstring(err));
        abort();
    }

    err = initialize_ram_alloc(2);
    if (err_is_fail(err)) {
        debug_printf("initialize_ram_alloc() failed: %s\n", err_getstring(err));
        abort();
    }

    err = forge_bootinfo_capabilities(bi, cap_mmstrings_frame);
    if (err_is_fail(err)) {
        debug_printf("forge_bootinfo_capabilities() failed: %s\n", err_getstring(err));
        abort();
    }

    err = monitorserver_init();
    if (err_is_fail(err)) {
        debug_printf("monitorserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    // Grading
    grading_test_early();

    domainid_t pid;
    struct spawninfo si;
    err = spawn_load_by_name("hello", &si, &pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "spawn_load_by_name");
        debug_printf("spawn_load_by_name() failed: %s\n", err_getstring(err));
        abort();
    }

    // Grading
    grading_test_late();

    while (true) {
        //thread_yield();
    }

#if 0
    debug_printf("Entering message handler loop...\n");

    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }
#endif

    return EXIT_SUCCESS;
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

    if (my_core_id == 0) {
        return first_main(argc, argv);
    } else {
        return other_main(argc, argv);
    }
}
