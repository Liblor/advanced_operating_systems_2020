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
#include <aos/deferred.h>

#include "first_main.h"

#include "mem_alloc.h"

#include "memoryserver.h"
#include "monitorserver.h"
#include "nameserver.h"
#include "serial/serialserver.h"
#include "serial/serial_facade.h"

extern coreid_t my_core_id;

struct nameserver_state ns_state;

static inline void start_server(char *service_name, char *cmd)
{
    errval_t err;

    domainid_t pid;
    struct spawninfo si;

    debug_printf("Spawning service '%s'.\n", service_name);

    err = spawn_load_by_name(cmd, &si, &pid);
    if (err_is_fail(err)) {
        debug_printf("spawn_load_by_name() failed: %s\n", err_getstring(err));
        abort();
    }
    debug_printf("Got pid %llu\n", pid);
}

static void setup_servers(
        void
)
{
    errval_t err;

    err = nameserver_init(&ns_state);
    if (err_is_fail(err)) {
        debug_printf("nameserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    err = memoryserver_init(ram_alloc_aligned_handler);
    if (err_is_fail(err)) {
        debug_printf("memoryserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    err = serialserver_init();
    if (err_is_fail(err)) {
        debug_printf("serialserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    err = monitorserver_init();
    if (err_is_fail(err)) {
        debug_printf("monitorserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    err = monitorserver_serve_lmp_in_thread();
    if (err_is_fail(err)) {
        debug_printf("monitorserver_serve_lmp_in_thread() failed: %s\n", err_getstring(err));
    }
}

static void register_service_channel(
        enum monitorserver_binding_type type,
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
    if (service_rpc == NULL) {
        debug_printf("malloc() failed\n");
        abort();
    }

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

    if (rpc == NULL) {
        err = monitorserver_register_service(type, frame);
        if (err_is_fail(err)) {
            debug_printf("monitorserver_register_service() failed: %s\n", err_getstring(err));
            abort();
        }
    } else {
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
}

/*
 * The following channels are needed.
 * - remote monitor to local memoryserver
 * - remote monitor to local processserver
 * - remote monitor to local processserver (for local tasks)
 * - remote monitor to local serialserver
 * - remote monitor to local nameserver
 *
 * If `rpc` is `NULL`, then initializes the local monitorserver.
 */
__unused
static void register_service_channels(
        struct aos_rpc *rpc,
        coreid_t mpid
)
{
    register_service_channel(MemoryserverUrpc, rpc, mpid, memoryserver_ump_add_client);
    register_service_channel(SerialserverUrpc, rpc, mpid, serialserver_add_client);
    register_service_channel(NameserverUrpc, rpc, mpid, nameserver_add_client);

    debug_printf("all service channels for core %d registered\n", mpid);
}

__unused
static void setup_core(
        struct bootinfo *bootinfo,
        coreid_t mpid,
        struct aos_rpc *rpc
){
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
     * Send the bootinfo message.
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

    debug_printf("sending bootinfo\n");
    err = aos_rpc_ump_send_message(rpc, rpc_message);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_send_message() failed: %s\n", err_getstring(err));
        abort();
    }

    register_service_channels(rpc, mpid);
}

static void serve_periodic_urpc_event(void *args) {
    errval_t err;

    err = serialserver_serve_next();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "in serialserver_serve_next");
        abort();
    }

    err = memoryserver_ump_serve_next();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "in memoryserver_ump_serve_next");
        abort();
    }
}

static errval_t setup_periodic_urpc_events(
        struct periodic_event *periodic_urpc_ev
){
    errval_t  err;

    memset(periodic_urpc_ev, 0, sizeof(struct periodic_event));

    err = periodic_event_create(periodic_urpc_ev,
                                get_default_waitset(),
                                PERIODIC_URPC_EVENT_US_FIRST,
                                MKCLOSURE(serve_periodic_urpc_event, NULL));
    return err;
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

    nameserver_serve_in_thread(&ns_state);

    register_service_channels(NULL, my_core_id);

    start_server(NAMESERVICE_INIT, "initserver");
    start_server(NAMESERVICE_PROCESS, "processserver");

#if 0
    struct aos_rpc rpc_core1;
    setup_core(bi, 1, &rpc_core1);
#endif

    struct periodic_event periodic_urpc_ev;
    err = setup_periodic_urpc_events(&periodic_urpc_ev);
    if (err_is_fail(err)) {
        debug_printf("failed to call setup_periodic_urpc_events: %s\n", err_getstring(err));
        abort();
    }

    // Grading
    grading_test_late();

#if 1
    domainid_t pid;
    struct spawninfo si;
    err = spawn_load_by_name("aosh", &si, &pid);
    if (err_is_fail(err)) {
        debug_printf("spawn_load_by_name() failed: %s\n", err_getstring(err));
        abort();
    }
#endif

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
