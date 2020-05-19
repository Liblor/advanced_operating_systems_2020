#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>
#include <rpc/server/ump.h>

#include "serialserver.h"

static struct rpc_ump_server server;

static putchar_callback_t putchar_cb = NULL;
static getchar_callback_t getchar_cb = NULL;


static errval_t reply_char(struct aos_rpc *rpc, char c) {
    errval_t err;

    char buf[sizeof(struct rpc_message) + sizeof(char)];
    struct rpc_message *msg = (struct rpc_message*) &buf;

    msg->cap = NULL_CAP;
    msg->msg.method = Method_Serial_Getchar;
    msg->msg.payload_length = sizeof(c);
    msg->msg.status = Status_Ok;
    msg->msg.payload[0] = c;

    err = aos_rpc_ump_send_message(rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "ump_send_message failed\n");
        return err;
    }

    return SYS_ERR_OK;
}

static void service_recv_cb(struct rpc_message *msg, void *callback_state, struct aos_rpc *rpc, void *server_state)
{
    errval_t err;

    char c;
    switch (msg->msg.method) {
    case Method_Serial_Putchar:
        memcpy(&c, msg->msg.payload, sizeof(char));
        if (putchar_cb != NULL) {
            putchar_cb(c);
        }
        break;
    case Method_Serial_Getchar:
        if (getchar_cb != NULL) {
            // TODO Currently, if this callback blocks (which is does if
            // the callback calls sys_getchar) the server cannot process
            // other requests. This could be solved by giving this callback
            // another callback to send the response, so that the server
            // doesn't have to wait for this callback to complete.
            getchar_cb(&c);
            err = reply_char(rpc, c);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "reply_char() failed");
            }
        }
        break;
    default:
        break;
    }
}

errval_t serialserver_add_client(struct aos_rpc *rpc, coreid_t mpid)
{
    return rpc_ump_server_add_client(&server, rpc);
}

errval_t serialserver_serve_next(void)
{
    return rpc_ump_server_serve_next(&server);
}

errval_t serialserver_init(
    putchar_callback_t new_putchar_cb,
    getchar_callback_t new_getchar_cb
)
{
    errval_t err;

    putchar_cb = new_putchar_cb;
    getchar_cb = new_getchar_cb;

    err = rpc_ump_server_init(&server, service_recv_cb, NULL, NULL, NULL);
    if (err_is_fail(err)) {
        debug_printf("rpc_ump_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
