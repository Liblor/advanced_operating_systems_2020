#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

#include <rpc/server/lmp.h>

#include "initserver.h"

static struct rpc_lmp_server server;

static recv_number_callback_t recv_number_cb = NULL;
static recv_string_callback_t recv_string_cb = NULL;

static void service_recv_cb(struct rpc_message *msg, void *shared_state)
{
    uintptr_t num;
    size_t last_idx;

	switch (msg->msg.method) {
    case Method_Send_Number:
        memcpy(&num, msg->msg.payload, sizeof(uint64_t));

        if (recv_number_cb != NULL) {
            recv_number_cb(num);
        }
        break;
    case Method_Send_String:
        // Make sure that the string is null-terminated
        last_idx = msg->msg.payload_length - 1;
        msg->msg.payload[last_idx] = '\0';

        if (recv_number_cb != NULL) {
            recv_string_cb(msg->msg.payload);
        }
        break;
    default:
        break;
	}
}

// Initialize channel-specific data.
static void state_init_cb(void *arg)
{
#if 0
    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    common_state->shared = malloc(sizeof(struct initserver_cb_state));
    struct initserver_cb_state *state = common_state->shared;
#endif
}

// Free channel-specific data.
static void state_free_cb(void *arg)
{
}

errval_t initserver_init(
    recv_number_callback_t new_recv_number_cb,
    recv_string_callback_t new_recv_string_cb
)
{
    errval_t err;

    recv_number_cb = new_recv_number_cb;
    recv_string_cb = new_recv_string_cb;

    err = rpc_lmp_server_init(&server, cap_chan_init, service_recv_cb, state_init_cb, state_free_cb);
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
