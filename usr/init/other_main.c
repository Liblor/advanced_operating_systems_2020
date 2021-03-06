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
#include <aos/nameserver.h>
#include <aos/dispatcher_arch.h>

#include "other_main.h"

#include "mem_alloc.h"

#include "memoryserver.h"
#include "monitorserver.h"

static void receive_bootinfo(
    struct aos_rpc *rpc,
    struct bootinfo **bootinfo,
    struct capref *cap
)
{
    errval_t err;

    struct rpc_message *rpc_message = NULL;

    err = aos_rpc_ump_receive(rpc, &rpc_message);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_receive() failed: %s\n", err_getstring(err));
        abort();
    }

    assert(rpc_message != NULL);
    assert(rpc_message->msg.payload_length >= sizeof(struct bootinfo));
    assert(rpc_message->msg.status == Status_Ok);
    assert(rpc_message->msg.method == Method_Send_Bootinfo);

    *bootinfo = malloc(rpc_message->msg.payload_length);
    memcpy(*bootinfo, rpc_message->msg.payload, rpc_message->msg.payload_length);

    *cap = rpc_message->cap;

    free(rpc_message);
}

static void register_service_channel(
        enum monitorserver_binding_type type,
        struct aos_rpc *rpc
){
    errval_t err;

    struct rpc_message *rpc_message = NULL;

    err = aos_rpc_ump_receive(rpc, &rpc_message);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_receive() failed: %s\n", err_getstring(err));
        abort();
    }

    assert(rpc_message != NULL);
    assert(rpc_message->msg.payload_length == 0);
    assert(rpc_message->msg.status == Status_Ok);
    assert(rpc_message->msg.method == Method_Send_Binding);

    monitorserver_register_service(type, rpc_message->cap);

    free(rpc_message);
}

static void register_service_channels(
    struct aos_rpc *rpc
)
{
    register_service_channel(MemoryserverUrpc, rpc);
    register_service_channel(NameserverUrpc, rpc);

    debug_printf("all register_service_channel registered\n");
}


int other_main(int argc, char *argv[])
{
    dispatcher_handle_t handle_child = curdispatcher();
    struct dispatcher_generic *disp_gen = get_dispatcher_generic(handle_child);
    disp_gen->domain_id = 1;

    errval_t err;
    struct aos_rpc rpc;

    err = aos_rpc_ump_init(&rpc, cap_urpc, false);
    assert(err_is_ok(err));

    struct capref cap_mmstrings_frame;
    receive_bootinfo(&rpc, &bi, &cap_mmstrings_frame);

    grading_setup_app_init(bi);

    err = forge_bootinfo_ram(bi);
    if (err_is_fail(err)) {
        debug_printf("forge_bootinfo_ram() failed: %s\n", err_getstring(err));
        abort();
    }

    err = initialize_ram_alloc(AOS_CORE_COUNT);
    if (err_is_fail(err)) {
        debug_printf("initialize_ram_alloc() failed: %s\n", err_getstring(err));
        abort();
    }

    err = forge_bootinfo_capabilities(bi, cap_mmstrings_frame);
    if (err_is_fail(err)) {
        debug_printf("forge_bootinfo_capabilities() failed: %s\n", err_getstring(err));
        abort();
    }

    // Setup local memory server
    err = memoryserver_init(ram_alloc_aligned_handler);
    if (err_is_fail(err)) {
        debug_printf("memoryserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    err = monitorserver_init(NULL);
    if (err_is_fail(err)) {
        debug_printf("monitorserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    register_service_channels(&rpc);

    // Grading
    grading_test_early();

    // Grading
    grading_test_late();

#if 0
    domainid_t pid;
    struct spawninfo si;
    err = spawn_load_by_name("hello", &si, &pid);
    if (err_is_fail(err)) {
        debug_printf("spawn_load_by_name() failed: %s\n", err_getstring(err));
        abort();
    }
#endif

    debug_printf("Entering message handler loop...\n");

    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        // TODO Switch to event_dispatch_non_block() and add UMP server serve_next calls like in first_main.c
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }

        thread_yield();
    }

    return EXIT_SUCCESS;
}
