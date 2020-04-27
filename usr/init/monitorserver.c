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

}

// XXX: API is changed to have one cap for rx and tx
// XXX: Decide if one thread for all localtask services or one thread for each local task service (ie spawn, memory)
__unused
static int
serve_localtasks_thread(void * args) {
    errval_t err;

    struct capref cap_localtasks_spawn;
    struct aos_rpc rpc_localtasks_spawn_monitor;

    // XXX: API to change, use one cap for tx, rx
    err = aos_rpc_ump_init(&rpc_localtasks_spawn_monitor, cap_localtasks_spawn);
    assert(err_is_ok(err));

    err = aos_rpc_ump_set_rx(&rpc_localtasks_spawn_monitor, cap_localtasks_spawn);
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



//static struct serve_localtasks_args {
//
//};


errval_t monitorserver_init(void)
{
    errval_t err;

    err = rpc_lmp_server_init(&server, cap_chan_monitor, service_recv_cb, state_init_cb, state_free_cb, NULL);
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
