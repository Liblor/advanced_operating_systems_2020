#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/aos_rpc_lmp_marshal.h>
#include <aos/nameserver.h>

#include <rpc/server/lmp.h>
#include <spawn/spawn.h>

#include "monitorserver.h"
#include "nameserver.h"

static struct monitorserver_state monitorserver_state;

#define MONITORSERVER_LOCK thread_mutex_lock(&monitorserver_state.mutex)
#define MONITORSERVER_UNLOCK thread_mutex_unlock(&monitorserver_state.mutex)

//#define trace(msg...) debug_printf(msg)
#define trace(msg...)  ((void)0)

static errval_t reply_error(
        struct aos_rpc *rpc,
        enum rpc_message_method method
)
{
    errval_t err;
    struct rpc_message msg;

    msg.cap = NULL_CAP;
    msg.msg.method = method;
    msg.msg.payload_length = 0;
    msg.msg.status = Status_Error;

    err = aos_rpc_lmp_send_message(rpc, &msg, LMP_SEND_FLAGS_DEFAULT);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_send_message failed\n");
        return err;
    }
    return SYS_ERR_OK;
}

static inline errval_t monitor_forward_request(
        struct monitorserver_state *mss,
        struct rpc_message *msg,
        struct aos_rpc *rpc_reply,
        struct aos_rpc *forward_to
)
{
    errval_t err;

    assert(rpc_reply != NULL);

    err = aos_rpc_ump_send_message(forward_to, msg);
    if (err_is_fail(err)) {
        err = reply_error(rpc_reply, msg->msg.method);
    }

    rpc_lmp_server_pause_processing(&mss->lmp_server);
    mss->rpc_forward_request_pending = forward_to;
    mss->rpc_forward_response_pending = rpc_reply;
    mss->method_forward_request_pending = msg->msg.method;

    return err;
}

static inline errval_t monitor_try_forward_response(
        struct monitorserver_state *mss
)
{
    errval_t err = SYS_ERR_OK;

    struct rpc_message *recv = NULL;

    // Check if we are waiting for a response to forward
    if (mss->rpc_forward_request_pending != NULL) {
        // Try to receive response of the forwarded request
        err = aos_rpc_ump_receive_non_block(mss->rpc_forward_request_pending, &recv);
        if (err_is_fail(err)) {
            err = reply_error(mss->rpc_forward_response_pending, mss->method_forward_request_pending);
            goto cleanup;
        }

        if (recv != NULL) {
            // Response received
            err = aos_rpc_lmp_send_message(mss->rpc_forward_response_pending, recv, LMP_SEND_FLAGS_DEFAULT);

            mss->rpc_forward_request_pending = NULL;
            mss->rpc_forward_response_pending = NULL;
            rpc_lmp_server_start_processing(&mss->lmp_server);
        }
    }

cleanup:
    if (recv != NULL) {
        free(recv);
    }
    return err;
}

static void forward_response_periodic_event_func(void *arg)
{
    errval_t err;

    assert(arg != NULL);

    struct monitorserver_state *mss = arg;

    err = monitor_try_forward_response(mss);
	if (err_is_fail(err)) {
	    debug_printf("Unhandled error in monitorserver forward_response_periodic_event_func()\n");
	}
}

static inline errval_t monitor_forward(
        struct rpc_message *msg,
        struct aos_rpc *forward_to
)
{
    errval_t err;
    err = aos_rpc_ump_send_message(
            forward_to,
            msg
    );
    return err;
}

__inline
static bool is_registered(struct monitorserver_rpc *rpc) {
    bool res;
    MONITORSERVER_LOCK;
    res = rpc->is_registered;
    MONITORSERVER_UNLOCK;
    return res;
}

static void service_recv_cb(
        struct rpc_message *msg,
        void *callback_state,
        struct aos_rpc *rpc,
        void *server_state
)
{
    trace("monitorserver#service_recv_cb method: %d\n", msg->msg.method);

    errval_t err = SYS_ERR_OK;
    struct monitorserver_state *mss = server_state;
	switch (msg->msg.method) {
    case Method_Get_Ram_Cap:
        if (! is_registered(&mss->memoryserver_rpc)) {
            goto unregistered_service;
        }
        err = monitor_forward_request(mss, msg, rpc, &mss->memoryserver_rpc.ump_rpc);
        break;
    case Method_Nameserver_Register:
    case Method_Nameserver_Deregister:
    case Method_Nameserver_Lookup:
    case Method_Nameserver_Enumerate:
        if (! is_registered(&mss->nameserver_rpc)) {
            goto unregistered_service;
        }
        err = monitor_forward_request(mss, msg, rpc, &mss->nameserver_rpc.ump_rpc);
        break;
    case Method_Block_Driver_Read_Block:
    case Method_Block_Driver_Write_Block:
            if (! is_registered(&mss->blockdriverserver_rpc)) {
                goto unregistered_service;
            }
            err = monitor_forward_request(mss, msg, rpc, &mss->blockdriverserver_rpc.ump_rpc);
            break;
	default:
        debug_printf("monitorserver unknown method given: type: %d\n", msg->msg.method);
	}
	if (err_is_fail(err)) {
	    debug_printf("Unhandled error in monitorserver service_recv_cb\n");
	}

    trace("exit monitorserver#service_recv_cb: method %d\n", msg->msg.method);
	return;

	unregistered_service:
        debug_printf("service method %d is not registered. cannot service\n", msg->msg.method);
}

// Initialize channel-specific data.
static void *state_init_cb(
        void *server_state
){
    struct monitorserver_cb_state *state = NULL;

    return state;
}

// Free channel-specific data.
static void state_free_cb(
        void *server_state,
        void *callback_state
){
    struct monitorserver_cb_state *state = callback_state;
    free(state);
}

// local task action to spawn a process on core
static errval_t serve_localtask_spawn(
        struct rpc_message* recv_msg,
        struct rpc_message** answer
){

    assert(recv_msg != NULL);

    switch(recv_msg->msg.method) {
        case Method_Localtask_Spawn_Process: {
            errval_t err;
            domainid_t pid = *((domainid_t *) recv_msg->msg.payload);
            char *name = recv_msg->msg.payload + sizeof(domainid_t);

            enum rpc_message_status status = Status_Ok;
            {
                struct spawninfo si;
                err = spawn_load_by_name(name, &si, &pid);
            }
            if (err_is_fail(err)) {
                debug_printf("spawn_cb in local task failed: %s\n", err_getstring(err));
                status = Spawn_Failed;
            }
            *answer = malloc(sizeof(struct rpc_message));
            if (*answer == NULL) {
                return LIB_ERR_MALLOC_FAIL;
            }
            (*answer)->cap = NULL_CAP;
            (*answer)->msg.payload_length = 0;
            (*answer)->msg.method = Method_Localtask_Spawn_Process;
            (*answer)->msg.status = status;
            break;
        }
        default:
            debug_printf("unknown localtask: %d\n", recv_msg->msg.method);
    }

    return SYS_ERR_OK;
}

/** initialize a urpc channel **/
static errval_t initialize_service(struct monitorserver_rpc *rpc,
                                   struct capref frame) {
    errval_t err;

    if (rpc->is_registered == true) {
        return AOS_ERR_MONITOR_ALREADY_REGISTERED_RPC;
    }

    err = aos_rpc_ump_init(
            &rpc->ump_rpc,
            frame,
            false
    );
    if (err_is_fail(err)) {
        return err;
    }
    rpc->is_registered = true;

    return SYS_ERR_OK;
}

static void service_localtask_handler(void *st, void *message, size_t bytes, void **response, size_t *response_bytes, struct capref tx_cap, struct capref *rx_cap)
{
    errval_t err;

    //struct monitorserver_state server_state = st;
    struct rpc_message *msg = message;
    struct rpc_message *resp = NULL;

    err = serve_localtask_spawn(msg, &resp);
    if (err_is_fail(err)) {
        debug_printf("serve_localtask_spawn() failed: %s", err_getstring(err));
        return;
    }

    *response = resp;
    *response_bytes = sizeof(struct rpc_message) + resp->msg.payload_length;
}

errval_t monitorserver_register_service(
        enum monitorserver_binding_type type,
        struct capref urpc_frame
){
    errval_t err;
    MONITORSERVER_LOCK;

    switch(type) {
        case SerialserverUrpc:
            err = initialize_service(&monitorserver_state.serialserver_rpc, urpc_frame);
            break;
        case MemoryserverUrpc:
            err = initialize_service(&monitorserver_state.memoryserver_rpc, urpc_frame);
            break;
        case BlockDriverServerUrpc:
            err = initialize_service(&monitorserver_state.blockdriverserver_rpc, urpc_frame);
            break;
        case NameserverUrpc:
            debug_printf("Registering nameserver at monitor.\n");
            err = initialize_service(&monitorserver_state.nameserver_rpc, urpc_frame);
            break;
        default:
            debug_printf("unknown type: %d\n", type);
            err = RPC_ERR_INITIALIZATION;
            break;
    }

    MONITORSERVER_UNLOCK;

    if (err_is_fail(err)) {
        debug_printf("initialize_monitorserver_state() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    if (type == NameserverUrpc) {
        // Once the nameserver is registered at the monitor the monitor can register itself at the nameserver
        debug_printf("Nameserver registered at monitor, registering monitor at nameserver...\n");

        coreid_t cid = disp_get_core_id();
        char service_name[AOS_RPC_NAMESERVER_MAX_NAME_LENGTH + 1];
        snprintf(service_name, sizeof(service_name), NAMESERVICE_MONITOR "%llu", cid);

        if (monitorserver_state.ns_state == NULL) {
            err = nameservice_register(service_name, service_localtask_handler, &monitorserver_state);
            if (err_is_fail(err)) {
                debug_printf("nameservice_register() failed: %s\n", err_getstring(err));
                return err;
            }
        } else {
            err = nameservice_register_no_send(service_name, service_localtask_handler, &monitorserver_state);
            if (err_is_fail(err)) {
                debug_printf("nameservice_register() failed: %s\n", err_getstring(err));
                return err;
            }

            struct srv_entry *monservice = nameservice_get_entry(service_name);
            assert(monservice != NULL);

            err = nameserver_add_service(monitorserver_state.ns_state, service_name, monservice->add_client_chan.ump.frame_cap, 0);
            if (err_is_fail(err)) {
                debug_printf("monitorserver_init() failed: %s\n", err_getstring(err));
                abort();
            }
        }
    }

    return SYS_ERR_OK;
}

static int serve_lmp_requests_th(void *args) {
    errval_t err;
    struct waitset *ws = &monitorserver_state.ws;

    while (true) {
        err = event_dispatch(ws);
        if (err_is_fail(err)) {
            debug_printf("error in serving lmp requests, %s\n", err_getstring(err));
        }
    }

    return SYS_ERR_OK;
}

/** serves lmp requests in own thread **/
errval_t monitorserver_serve_lmp_in_thread(void) {
    struct thread *th = thread_create(serve_lmp_requests_th, NULL);
    if (th == NULL) {
        return LIB_ERR_THREAD_CREATE;
    }

    return SYS_ERR_OK;
}

errval_t monitorserver_init(struct nameserver_state *ns_state)
{
    errval_t err;

    coreid_t cid = disp_get_core_id();
    debug_printf("Initializing Monitor on core %llu.\n", cid);

    memset(&monitorserver_state, 0, sizeof(struct monitorserver_state));
    monitorserver_state.ns_state = ns_state;
    thread_mutex_init(&monitorserver_state.mutex);
    waitset_init(&monitorserver_state.ws);

    memset(&monitorserver_state.forward_response_periodic_ev, 0, sizeof(struct periodic_event));
    err = periodic_event_create(&monitorserver_state.forward_response_periodic_ev,
                                get_default_waitset(),
                                MONITORSERVER_PERIODIC_FORWARD_RESPONSE_EVENT_US,
                                MKCLOSURE(forward_response_periodic_event_func, &monitorserver_state));

    err = rpc_lmp_server_init(
            &monitorserver_state.lmp_server, cap_chan_monitor,
            service_recv_cb,
            state_init_cb,
            state_free_cb,
            &monitorserver_state,
            get_default_waitset());

    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
