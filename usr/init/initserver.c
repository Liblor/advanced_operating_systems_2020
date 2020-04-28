#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>

#include <rpc/server/ump.h>

#include "initserver.h"

static struct rpc_ump_server server;

static recv_number_callback_t recv_number_cb = NULL;
static recv_string_callback_t recv_string_cb = NULL;

static void service_recv_cb(struct rpc_message *msg, void *callback_state, struct aos_rpc *rpc, void *server_state)
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

errval_t initserver_add_client(struct aos_rpc *rpc, coreid_t mpid)
{
    return rpc_ump_server_add_client(&server, rpc);
}

errval_t initserver_serve_next(void)
{
    return rpc_ump_server_serve_next(&server);
}

errval_t initserver_init(
    recv_number_callback_t new_recv_number_cb,
    recv_string_callback_t new_recv_string_cb
)
{
    errval_t err;

    recv_number_cb = new_recv_number_cb;
    recv_string_cb = new_recv_string_cb;

    err = rpc_ump_server_init(&server, service_recv_cb, NULL, NULL, NULL);
    if (err_is_fail(err)) {
        debug_printf("rpc_ump_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
