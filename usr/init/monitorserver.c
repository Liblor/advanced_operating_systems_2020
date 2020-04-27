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
        void *callback_state,
        struct aos_rpc *rpc,
        void *server_state
)
{
    errval_t err;
    struct monitorserver_state *mss = server_state;
    struct rpc_message *recv;
    err = aos_rpc_ump_send_and_wait_recv(
            &mss->server_rpc,
            msg,
            &recv
    );
    if (err_is_fail(err)) {
        err = reply_error(rpc, msg->msg.method);
        goto cleanup;
    }
    err = aos_rpc_lmp_send_message(rpc, recv, LMP_SEND_FLAGS_DEFAULT);
cleanup:
    if (recv != NULL) {
        free(recv);
    }
    return err;
}


static inline errval_t monitor_forward(
        struct rpc_message *msg,
        void *callback_state,
        struct aos_rpc *rpc,
        void *server_state
)
{
    errval_t err;
    struct monitorserver_state *mss = server_state;
    err = aos_rpc_ump_send_message(
            &mss->server_rpc,
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
	switch (msg->msg.method) {
    case Method_Get_Ram_Cap:
        err = monitor_forward_receive(msg, callback_state, rpc, server_state);
        break;
    case Method_Send_Number:
    case Method_Send_String:
        err = monitor_forward(msg, callback_state, rpc, server_state);
        break;
    case Method_Serial_Putchar:
        err = monitor_forward(msg, callback_state, rpc, server_state);
        break;
    case Method_Serial_Getchar:
        err = monitor_forward_receive(msg, callback_state, rpc, server_state);
        break;
    case Method_Process_Get_Name:
    case Method_Process_Get_All_Pids:
    case Method_Spawn_Process:
        err = monitor_forward_receive(msg, callback_state, rpc, server_state);
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

errval_t monitorserver_init(void
)
{
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

    return SYS_ERR_OK;
}
