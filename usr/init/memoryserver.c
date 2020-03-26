#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

#include <rpc/server/lmp.h>

#include "memoryserver.h"

static struct rpc_lmp_server server;

static ram_cap_callback_t ram_cap_cb = NULL;

static errval_t reply_cap(struct lmp_chan *lc, struct capref *cap, size_t bytes) {
    errval_t err;

    uint8_t msg_buf[sizeof(struct rpc_message) + sizeof(bytes)];
    struct rpc_message *msg = (void *) msg_buf;

    msg->cap = cap;
    msg->msg.method = Method_Get_Ram_Cap;
    msg->msg.payload_length = sizeof(bytes);
    msg->msg.status = Status_Ok;
    memcpy(msg->msg.payload, &bytes, sizeof(bytes));

    err = aos_rpc_lmp_send_message(lc, msg, LMP_SEND_FLAGS_DEFAULT);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_send_message failed\n");
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t reply_error(struct lmp_chan *lc) {
    errval_t err;

    struct rpc_message msg;

    msg.cap = NULL;
    msg.msg.method = Method_Get_Ram_Cap;
    msg.msg.payload_length = 0;
    msg.msg.status = Status_Error;

    err = aos_rpc_lmp_send_message(lc, &msg, LMP_SEND_FLAGS_DEFAULT);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_send_message failed\n");
        return err;
    }

    return SYS_ERR_OK;
}

// Allocate RAM and send it to the client. Also, we notify our dispatcher that
// we allocated RAM.
static void service_recv_cb(void *arg)
{
    errval_t err;

    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    struct aos_rpc *rpc = &common_state->rpc;
    struct lmp_chan *lc = &rpc->lc;
    //struct memoryserver_cb_state *state = common_state->shared;

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

    size_t bytes;
    size_t alignment;
    struct capref retcap;

    switch (rpc_msg_part->method) {
        case Method_Get_Ram_Cap:
            memcpy(&bytes, rpc_msg_part->payload, sizeof(bytes));
            memcpy(&alignment, rpc_msg_part->payload + sizeof(bytes), sizeof(alignment));

            if (ram_cap_cb != NULL) {
                size_t retbytes;
                err = ram_cap_cb(bytes, alignment, &retcap, &retbytes);
                if (err_is_fail(err)) {
                    err = reply_error(lc);
                }
                err = reply_cap(lc, &retcap, retbytes);
            } else {
                err = reply_error(lc);
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
    common_state->shared = malloc(sizeof(struct memoryserver_cb_state));
    struct memoryserver_cb_state *state = common_state->shared;
#endif
}

// Free channel-specific data.
static void state_free_cb(void *arg)
{
}

errval_t memoryserver_init(ram_cap_callback_t new_ram_cap_cb)
{
    errval_t err;

    ram_cap_cb = new_ram_cap_cb;

    err = rpc_lmp_server_init(&server, cap_chan_memory, service_recv_cb, state_init_cb, state_free_cb);
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
