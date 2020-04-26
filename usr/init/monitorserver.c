#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

#include <rpc/server/lmp.h>

#include "monitorserver.h"

static struct rpc_lmp_server server;

static void service_recv_cb(struct rpc_message *msg, void *callback_state, struct aos_rpc *rpc, void *server_state)
{
	switch (msg->msg.method) {
    case Method_Send_Number:
        break;
    case Method_Get_Ram_Cap:
        break;
    case Method_Send_String:
        break;
    case Method_Serial_Putchar:
        break;
    case Method_Serial_Getchar:
        break;
    case Method_Process_Get_Name:
        break;
    case Method_Process_Get_All_Pids:
        break;
    case Method_Spawn_Process:
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
    err = rpc_lmp_server_init(&server, cap_chan_init, service_recv_cb, state_init_cb, state_free_cb, NULL);
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
