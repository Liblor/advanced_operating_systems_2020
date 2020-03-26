#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

#include <rpc/server/lmp.h>

#include "serialserver.h"

static struct rpc_lmp_server server;

static putchar_callback_t putchar_cb = NULL;
static getchar_callback_t getchar_cb = NULL;

static errval_t reply_char(struct lmp_chan *lc, char c) {
    errval_t err;

    struct rpc_message msg;

    msg.cap = NULL;
    msg.msg.method = Method_Serial_Getchar;
    msg.msg.payload_length = sizeof(c);
    msg.msg.status = Status_Ok;
    msg.msg.payload[0] = c;

    err = aos_rpc_lmp_send_message(lc, &msg, LMP_SEND_FLAGS_DEFAULT);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_send_message failed\n");
        return err;
    }

    return SYS_ERR_OK;
}

static void service_recv_cb(void *arg)
{
    errval_t err;

    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    struct aos_rpc *rpc = &common_state->rpc;
    struct lmp_chan *lc = &rpc->lc;
    //struct serialserver_cb_state *state = common_state->shared;

    struct capref cap;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    err = lmp_chan_recv(lc, &msg, &cap);
    if (err_is_fail(err)) {
        if (!lmp_err_is_transient(err)) {
            DEBUG_ERR(err, "lmp_chan_recv() failed (not transient)");
        }
        return;
    }

    struct rpc_message_part *rpc_msg_part = (struct rpc_message_part *)msg.words;

    char c;
    switch (rpc_msg_part->method) {
        case Method_Serial_Putchar:
            memcpy(&c, rpc_msg_part->payload, sizeof(char));
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
                err = reply_char(lc, c);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "reply_char() failed");
                }
            }
            break;
        default:
            break;
    }
}

// Initialize channel-specific data.
static void state_init_cb(void *arg)
{
    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    common_state->shared = malloc(sizeof(struct serialserver_cb_state));
    //struct serialserver_cb_state *state = common_state->shared;
}

// Free channel-specific data.
static void state_free_cb(void *arg)
{
    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    free(common_state->shared);
}

errval_t serialserver_init(
    putchar_callback_t new_putchar_cb,
    getchar_callback_t new_getchar_cb
)
{
    errval_t err;

    putchar_cb = new_putchar_cb;
    getchar_cb = new_getchar_cb;

    err = rpc_lmp_server_init(&server, cap_chan_serial, service_recv_cb, state_init_cb, state_free_cb);
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
