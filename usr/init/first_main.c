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

#include "first_main.h"

#include "mem_alloc.h"

#include "initserver.h"
#include "memoryserver.h"
#include "serialserver.h"
#include "processserver.h"

#include "first_main.h"

static void number_cb(uintptr_t num)
{
    grading_rpc_handle_number(num);
#if 1
    debug_printf("number_cb(%llu)\n", num);
#endif
}

static void string_cb(char *c)
{
    grading_rpc_handler_string(c);
#if 1
    debug_printf("string_cb(%s)\n", c);
#endif
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

    err = memoryserver_init(ram_alloc_aligned_handler);
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
}

static void register_service_channel(
    struct aos_rpc *rpc,
    coreid_t mpid,
    errval_t (*register_func)(struct aos_rpc *rpc, coreid_t mpid)
)
{
    errval_t err;

    struct capref frame;

    err = frame_alloc(&frame, UMP_SHARED_FRAME_SIZE, NULL);
    if (err_is_fail(err)) {
        debug_printf("frame_alloc() failed: %s\n", err_getstring(err));
        abort();
    }

    struct aos_rpc *service_rpc = malloc(sizeof(struct aos_rpc));

    err = aos_rpc_ump_init(service_rpc, frame, true);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_init() failed: %s\n", err_getstring(err));
        abort();
    }

    err = register_func(service_rpc, mpid);
    if (err_is_fail(err)) {
        debug_printf("register_func() failed: %s\n", err_getstring(err));
        abort();
    }

    char buffer[sizeof(struct rpc_message)];
    memset(buffer, 0x00, sizeof(buffer));

    struct rpc_message *rpc_message = (struct rpc_message *) buffer;
    rpc_message->msg.payload_length = 0;
    rpc_message->msg.status = Status_Ok;
    rpc_message->msg.method = Method_Send_Binding;
    rpc_message->cap = frame;

    err = aos_rpc_ump_send_message(rpc, rpc_message);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_send_message() failed: %s\n", err_getstring(err));
        abort();
    }
}

/*
 * The following channels are needed.
 * - remote monitor to local initserver
 * - remote monitor to local memoryserver
 * - remote monitor to local processserver
 * - remote monitor to local processserver (for local tasks)
 * - remote monitor to local serialserver
 */
static void register_service_channels(
    struct aos_rpc *rpc,
    coreid_t mpid
)
{
    register_service_channel(rpc, mpid, initserver_add_client);
    register_service_channel(rpc, mpid, memoryserver_ump_add_client);
    register_service_channel(rpc, mpid, processserver_add_client);
    register_service_channel(rpc, mpid, processserver_set_local_task_chan);
    register_service_channel(rpc, mpid, serialserver_add_client);
}

static void setup_core(
    struct bootinfo *bootinfo,
    coreid_t mpid,
    struct aos_rpc *rpc
)
{
    errval_t err;

    /*
     * Setup the new UMP communication channels. The channels will be set up in
     * the order they are counted in.
     */

    struct capref frame;
    err = frame_alloc(&frame, UMP_SHARED_FRAME_SIZE, NULL);
    if (err_is_fail(err)) {
        debug_printf("frame_alloc() failed: %s\n", err_getstring(err));
        abort();
    }

    err = aos_rpc_ump_init(rpc, frame, true);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_init() failed: %s\n", err_getstring(err));
        abort();
    }

    /*
     * Boot the new core.
     */

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

    /*
     * Send the booinfo message.
     */

    const size_t size = sizeof(struct bootinfo) + bootinfo->regions_length * sizeof(struct mem_region);
    char buffer[sizeof(struct rpc_message) + size];
    memset(buffer, 0x00, sizeof(buffer));

    struct rpc_message *rpc_message = (struct rpc_message *) buffer;
    rpc_message->msg.payload_length = size;
    rpc_message->msg.status = Status_Ok;
    rpc_message->msg.method = Method_Send_Bootinfo;
    rpc_message->cap = cap_mmstrings;
    memcpy(rpc_message->msg.payload, bootinfo, size);

    err = aos_rpc_ump_send_message(rpc, rpc_message);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_send_message() failed: %s\n", err_getstring(err));
        abort();
    }

    register_service_channels(rpc, mpid);
}

int first_main(int argc, char *argv[])
{
    errval_t err;

    // Grading
    grading_setup_bsp_init(argc, argv);

    // First argument contains the bootinfo location, if it's not set
    bi = (struct bootinfo*) strtol(argv[1], NULL, 10);
    assert(bi != NULL);

    err = initialize_ram_alloc(AOS_CORE_COUNT);
    if(err_is_fail(err)){
        debug_printf("initialize_ram_alloc() failed: %s\n", err_getstring(err));
        abort();
    }

    // Grading
    grading_test_early();

    setup_servers();

    struct aos_rpc rpc_core1;
    setup_core(bi, 1, &rpc_core1);

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
        err = initserver_serve_next();
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in initserver_serve_next");
            abort();
        }

        err = serialserver_serve_next();
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in initserver_serve_next");
            abort();
        }

        err = processserver_serve_next();
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in initserver_serve_next");
            abort();
        }

        err = memoryserver_ump_serve_next();
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in initserver_serve_next");
            abort();
        }

        err = event_dispatch_non_block(default_ws);
        if (err != LIB_ERR_NO_EVENT &&  err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }

    return EXIT_SUCCESS;
}
