#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/aos_rpc_lmp_marshal.h>

#include <rpc/server/lmp.h>
#include <spawn/spawn.h>

#include "monitorserver.h"

static struct rpc_lmp_server server;
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

static inline errval_t monitor_forward_receive(
        struct rpc_message *msg,
        struct aos_rpc *rpc_reply,
        struct aos_rpc *forward_to
)
{
    errval_t err;
    struct rpc_message *recv = NULL;

    err = aos_rpc_ump_send_and_wait_recv(
            forward_to,
            msg,
            &recv
    );
    if (err_is_fail(err)) {
        err = reply_error(rpc_reply, msg->msg.method);
        goto cleanup;
    }
    err = aos_rpc_lmp_send_message(rpc_reply, recv, LMP_SEND_FLAGS_DEFAULT);
cleanup:
    if (recv != NULL) {
        free(recv);
    }
    return err;
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
        err = monitor_forward_receive(msg, rpc, &mss->memoryserver_rpc.ump_rpc);
        break;
    case Method_Send_Number:
    case Method_Send_String:
        if (! is_registered(&mss->initserver_rpc)) {
            goto unregistered_service;
        }
        err = monitor_forward(msg, &mss->initserver_rpc.ump_rpc);
        break;
    case Method_Serial_Putchar:
        if (! is_registered(&mss->serialserver_rpc)) {
            goto unregistered_service;
        }
        err = monitor_forward(msg, &mss->serialserver_rpc.ump_rpc);
        break;
    case Method_Serial_Getchar:
        if (! is_registered(&mss->serialserver_rpc)) {
            goto unregistered_service;
        }
        err = monitor_forward_receive(msg, rpc, &mss->serialserver_rpc.ump_rpc);
        break;
    case Method_Process_Get_Name:
    case Method_Process_Get_All_Pids:
    case Method_Spawn_Process:
        if (! is_registered(&mss->processserver_rpc)) {
            goto unregistered_service;
        }
        err = monitor_forward_receive(msg, rpc, &mss->processserver_rpc.ump_rpc);
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
            char *name = recv_msg->msg.payload;
            enum rpc_message_status status = Status_Ok;
            {
                struct spawninfo si;
                domainid_t ret_pid;
                err = spawn_load_by_name(name, &si, &ret_pid);
            }
            if (err_is_fail(err)) {
                debug_printf("spawn_cb in local task failed: %s", err_getstring(err));
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

/** callback which loops through localtasks urpc channels and checks for messages. **/
__unused
static void run_localtasks(void *args) {
    errval_t err;

    // XXX: This can easily be refactored to allow more localtasks in a generic manner.
    // for now we dont need more generic behaviour

    if (!is_registered(&monitorserver_state.processserver_localtasks_rpc)) {
        // nothing to do yet
        return;
    }

    struct rpc_message *msg_recv;
    struct rpc_message *answer;
    struct aos_rpc *localtask = &monitorserver_state.processserver_localtasks_rpc.ump_rpc;

    msg_recv = NULL;
    answer = NULL;
    err = aos_rpc_ump_receive_non_block(localtask, &msg_recv);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_receive_non_block: %s", err_getstring(err));
        goto err_clean_up;
    }
    else if (msg_recv != NULL) {

        err = serve_localtask_spawn(msg_recv, &answer);
        if (err_is_fail(err)) {
            debug_printf("serve_localtask_spawn: %s", err_getstring(err));
            goto err_clean_up;
        }
        if (answer != NULL) {
            err = aos_rpc_ump_send_message(localtask, answer);
            if (err_is_fail(err)) {
                debug_printf("aos_rpc_ump_send_message: failure in response: %s",
                        err_getstring(err));

                goto err_clean_up_answer;
            }
        }
        free(msg_recv);
        free(answer);
    }

    return;

err_clean_up_answer:
    free(answer);
err_clean_up:
    free(msg_recv);
    debug_printf("error occured in local tasks: %s", err_getstring(err));
}

errval_t monitorserver_register_service(
        enum monitorserver_binding_type type,
        struct capref urpc_frame
){
    errval_t err;
    MONITORSERVER_LOCK;

    switch(type) {
        case InitserverUrpc:
            err = initialize_service(&monitorserver_state.initserver_rpc, urpc_frame);
            break;
        case ProcessserverUrpc:
            err = initialize_service(&monitorserver_state.processserver_rpc, urpc_frame);
            break;
        case ProcessLocaltasksUrpc:
            err = initialize_service(&monitorserver_state.processserver_localtasks_rpc, urpc_frame);
            break;
        case SerialserverUrpc:
            err = initialize_service(&monitorserver_state.serialserver_rpc, urpc_frame);
            break;
        case MemoryserverUrpc:
            err = initialize_service(&monitorserver_state.memoryserver_rpc, urpc_frame);
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

errval_t monitorserver_init(void
){
    errval_t err;

    memset(&monitorserver_state, 0, sizeof(struct monitorserver_state));
    thread_mutex_init(&monitorserver_state.mutex);
    waitset_init(&monitorserver_state.ws);

    err = rpc_lmp_server_init(
            &server, cap_chan_monitor,
            service_recv_cb,
            state_init_cb,
            state_free_cb,
            &monitorserver_state,
            &monitorserver_state.ws);

    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }


    err = periodic_event_create(&monitorserver_state.periodic_localtask,
                                get_default_waitset(),
                                PERIODIC_LOCALTASKS_US,
                                MKCLOSURE(run_localtasks, NULL));

    if (err_is_fail(err)) {
        debug_printf("periodic_event_create() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }


    return SYS_ERR_OK;
}
