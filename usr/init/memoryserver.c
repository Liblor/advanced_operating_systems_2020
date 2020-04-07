#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

#include <rpc/server/lmp.h>
#include <aos/aos_rpc_lmp_marshal.h>

#include "memoryserver.h"

static struct rpc_lmp_server server;

static ram_cap_callback_t ram_cap_cb = NULL;

static errval_t reply_cap(struct lmp_chan *lc, struct capref *cap, size_t bytes) {
    errval_t err;

    char msg_buf[sizeof(struct rpc_message) + sizeof(bytes)];
    struct rpc_message *msg = (void *) msg_buf;

    msg->cap = *cap;
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

    msg.cap = NULL_CAP;
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
static void service_recv_cb(struct rpc_message *msg, void *callback_state, struct lmp_chan *reply_chan, void *server_state)
{
    errval_t err;

    size_t bytes;
    size_t alignment;
    struct capref retcap;

    // TODO: error handling not good!
    switch (msg->msg.method) {
    case Method_Get_Ram_Cap:
        memcpy(&bytes, msg->msg.payload, sizeof(bytes));
        memcpy(&alignment, msg->msg.payload + sizeof(bytes), sizeof(alignment));

        if (ram_cap_cb != NULL) {
            size_t retbytes;
            err = ram_cap_cb(bytes, alignment, &retcap, &retbytes);
            if (err_is_fail(err)) {
                err = reply_error(reply_chan);
            }
            err = reply_cap(reply_chan, &retcap, retbytes);
        } else {
            err = reply_error(reply_chan);
        }
        break;
    default:
        break;
    }
}

// Initialize channel-specific data.
static void *state_init_cb(void *server_state)
{
    struct memoryserver_cb_state *state = NULL;

    return state;
}

// Free channel-specific data.
static void state_free_cb(void *server_state, void *callback_state)
{
    struct memoryserver_cb_state *state = callback_state;
    free(state);
}

errval_t memoryserver_init(ram_cap_callback_t new_ram_cap_cb)
{
    errval_t err;

    ram_cap_cb = new_ram_cap_cb;

    err = rpc_lmp_server_init(&server, cap_chan_memory, service_recv_cb, state_init_cb, state_free_cb, NULL);
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
