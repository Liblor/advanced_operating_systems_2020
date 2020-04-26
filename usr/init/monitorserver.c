#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

#include <rpc/server/lmp.h>

#include "monitorserver.h"

static struct rpc_lmp_server server;

static void service_recv_cb(struct rpc_message *msg, void *callback_state, struct aos_rpc *rpc, void *server_state)
{
	switch (msg->msg.method) {
    case Method_Get_Ram_Cap:
        // TODO: forward msg to mem server via urpc
        break;

    case Method_Send_Number:
    case Method_Send_String:
        // TODO: forward msg to init server via urpc
        break;

    case Method_Serial_Putchar:
    case Method_Serial_Getchar:
        // TODO: forward msg to serial server via urpc
        break;

    case Method_Process_Get_Name:
    case Method_Process_Get_All_Pids:
    case Method_Spawn_Process:
        // TODO: forward msg to process server via urpc
        break;

	default:
	        debug_printf("monitor server: unknown msg->msg.method given: type: %d\n", msg->msg.method);
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

    // TODO change cap to new monitor cap
    err = rpc_lmp_server_init(&server, cap_chan_monitor, service_recv_cb, state_init_cb, state_free_cb, NULL);
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
