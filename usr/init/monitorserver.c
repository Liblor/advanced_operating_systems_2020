#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/aos_rpc_lmp_marshal.h>

#include <rpc/server/lmp.h>

#include "monitorserver.h"

static struct rpc_lmp_server server;

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
    struct rpc_message *recv;
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

static void service_recv_cb(
        struct rpc_message *msg,
        void *callback_state,
        struct aos_rpc *rpc,
        void *server_state
)
{
    errval_t err = SYS_ERR_OK;
    struct monitorserver_state *mss = server_state;
	switch (msg->msg.method) {
    case Method_Get_Ram_Cap:
        err = monitor_forward_receive(msg, rpc, &mss->memoryserver);
        break;
    case Method_Send_Number:
    case Method_Send_String:
        err = monitor_forward(msg, &mss->initserver);
        break;
    case Method_Serial_Putchar:
        err = monitor_forward(msg, &mss->serialserver);
        break;
    case Method_Serial_Getchar:
        err = monitor_forward_receive(msg, rpc, &mss->serialserver);
        break;
    case Method_Process_Get_Name:
    case Method_Process_Get_All_Pids:
    case Method_Spawn_Process:
        err = monitor_forward_receive(msg, rpc, &mss->processserver);
        break;

	default:
        debug_printf("monitor server: unknown msg->msg.method given: type: %d\n", msg->msg.method);
	}
	if (err_is_fail(err)) {
	    debug_printf("Unhandled error in monitorserver service_recv_cb\n");
	}
}

// Initialize channel-specific data.
static void *state_init_cb(void *server_state)
{
    struct monitorserver_cb_state *state = NULL;

    return state;
}

// Free channel-specific data.
static void state_free_cb(void *server_state, void *callback_state)
{
    struct monitorserver_cb_state *state = callback_state;
    free(state);
}


static errval_t serve_localtask_spawn(struct rpc_message* recv_msg, struct rpc_message** answer) {
    assert(recv_msg != NULL);

    switch(recv_msg->msg.method) {
        case Method_Localtask_Spawn_Process: {

            // TODO: do spawning
            debug_printf("TODO: do spawning as localtask\n");

            *answer = calloc(1, sizeof(struct rpc_message));
            if (*answer == NULL) {
                return LIB_ERR_MALLOC_FAIL;
            }
            (*answer)->cap = NULL_CAP;
            (*answer)->msg.method = Method_Localtask_Spawn_Process;
            (*answer)->msg.payload_length = 0;
            (*answer)->msg.status = Status_Ok;
            break;
        }

        default:
            debug_printf("unknown localtask: %d\n", recv_msg->msg.method);
    }

    return SYS_ERR_OK;
}

// XXX: API is changed to have one cap for rx and tx
// XXX: Decide if one thread for all localtask services or one thread for each local task service (ie spawn, memory)
__unused
static int
serve_localtasks_thread(void * args) {
    errval_t err;

    struct monitorserver_urpc_caps *urpc_caps = (struct monitorserver_urpc_caps *) args;

    struct capref cap_localtasks_spawn = urpc_caps->localtask_spawn;
    struct aos_rpc rpc_localtasks_spawn_monitor;

    // XXX: API to change, use one cap for tx, rx
    err = aos_rpc_ump_init(&rpc_localtasks_spawn_monitor, cap_localtasks_spawn, false);
    assert(err_is_ok(err));

    assert(err_is_ok(err));

    struct rpc_message *msg_recv = NULL;

    while(true) {
        err = aos_rpc_ump_receive_non_block(&rpc_localtasks_spawn_monitor, &msg_recv);
        if (err_is_fail(err)) {
            debug_printf("aos_rpc_ump_receive_non_block: %s", err_getstring(err));
            return err;
        }
        else if (msg_recv != NULL) {
            // do local tasks for spawn
            struct rpc_message *answer = NULL;
            err = serve_localtask_spawn(msg_recv, &answer);
            if (err_is_fail(err)) {
                debug_printf("serve_localtask_spawn: %s", err_getstring(err));
                return err;
            }
            if (answer != NULL) {
                err = aos_rpc_ump_send_message(&rpc_localtasks_spawn_monitor, answer);
                if (err_is_fail(err)) {
                    debug_printf("aos_rpc_ump_send_message: failure in response: %s", err_getstring(err));
                    return err;
                }
            }
            free(msg_recv);
            free(answer);
            answer = NULL;
            msg_recv = NULL;
        }
        // TODO local tasks for other servers
    }
}


errval_t monitorserver_init(
        struct monitorserver_urpc_caps *urpc_caps
){

    errval_t err;
    struct monitorserver_state *mss = calloc(1, sizeof(struct monitorserver_state));
    if (mss == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    // TODO: initialize monitorserver state with aos_rpc to urpc-server

    err = rpc_lmp_server_init(&server, cap_chan_monitor, service_recv_cb, state_init_cb, state_free_cb, mss);
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    // TODO: spawn thread
//    struct monitor_localtasks_args localtasks_args;
//    localtasks_args.urpc_localtask_spawn = NULL_CAP;
//    struct thread *localtasks_th = thread_create(serve_localtasks_thread, &localtasks_args);
//    if (localtasks_th == NULL){
//        debug_printf("err in creating localtasks thread, is NULL");
//        return LIB_ERR_THREAD_CREATE;
//    }


    return SYS_ERR_OK;
}
