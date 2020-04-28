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

#if 0
    // TODO Remove this test
    if (strcmp(name, "initserver") == 0) {
        struct aos_rpc init_rpc;
        err = aos_rpc_ump_init(&init_rpc, rpc_message->cap, false);
        assert(err_is_ok(err));

        uintptr_t payload = 123;
        size_t size = sizeof(uintptr_t);

        char buffer[sizeof(struct rpc_message) + size];
        struct rpc_message *msg = (struct rpc_message *) buffer;
        msg->msg.payload_length = size;
        msg->msg.status = Status_Ok;
        msg->msg.method = Method_Send_Number;
        msg->cap = NULL_CAP;
        memcpy(msg->msg.payload, &payload, size);

        for (int i = 0; i < 10; i++) {
            err = aos_rpc_ump_send_message(&init_rpc, msg);
            assert(err_is_ok(err));
        }
    }

#endif

    free(rpc_message);
}

static void register_service_channels(
    struct aos_rpc *rpc
)
{
    register_service_channel(InitserverUrpc, rpc);
    register_service_channel(MemoryserverUrpc, rpc);
    register_service_channel(ProcessserverUrpc, rpc);

    // This is the channel from which the monitor will receive local task requests.
    register_service_channel(ProcessLocaltasksUrpc, rpc);

    register_service_channel(SerialserverUrpc, rpc);

    debug_printf("all register_service_channel registered\n");
}


int other_main(int argc, char *argv[])
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

    err = monitorserver_init();
    if (err_is_fail(err)) {
        debug_printf("monitorserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    register_service_channels(&rpc);

    // Grading
    grading_test_early();

    // Grading
    grading_test_late();

#if 1
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
    }

    return EXIT_SUCCESS;
}
