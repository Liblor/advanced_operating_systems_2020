#include <aos/aos.h>
#include <aos/aos_rpc.h>

#include "initserver.h"

static struct capref open_ep;
static struct lmp_chan open_lc;

static struct capref service_ep;
static struct lmp_endpoint *service_lmp_ep;

static recv_number_callback_t recv_number_cb = NULL;
static recv_string_callback_t recv_string_cb = NULL;

// TODO: When another process terminates, free the associated channel.

static void service_recv_cb(void *arg)
{
    debug_printf("service_recv_cb()\n");

    struct callback_state *state = (struct callback_state *) arg;

    // accumulate message until full message was transmitted
    // check which message type was sent -> call corresponding callback
    // check if callback is null

    struct lmp_chan *lc = state->rpc.lc;
    struct capref cap;
    struct lmp_recv_msg msg;
    memset(&msg, 0, sizeof(struct lmp_recv_msg));

    errval_t err = lmp_chan_recv(lc, &msg, &cap);
    if (err_is_fail(err) && lmp_err_is_transient(err)) {
        // reregister
        err = lmp_chan_register_recv(lc, get_default_waitset(),
                                     MKCLOSURE(service_recv_cb, arg));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "");
            return;
        }
    }
    err = lmp_chan_register_recv(lc, get_default_waitset(),
                                 MKCLOSURE(service_recv_cb, arg));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "");
        return;
    }

    // TODO handle received error
    assert(msg.buf.buflen <= 4*sizeof(uint64_t));
    //assert(msg.buf.buflen >= 1*sizeof(uint64_t));

    // TODO message sanity check

    if (state->pending_state == EmptyState) {
        struct rpc_message_part *rpc_msg_part = (struct rpc_message_part *)msg.words;
        switch (rpc_msg_part->method) {
            case Method_Send_Number: {
                uint64_t num;
                memcpy(&num, rpc_msg_part->payload, sizeof(uint64_t));
                assert(recv_number_cb != NULL);     // TODO err handling
                recv_number_cb(lc, num);
                break;
            }
            case Method_Send_String: {
                state->string = malloc(rpc_msg_part->payload_length);
                if (state->string == NULL) {
                    // TODO Error handling
                }
                uint64_t to_copy = MIN(MAX_RPC_MSG_PART_PAYLOAD, rpc_msg_part->payload_length);
                strncpy(state->string, rpc_msg_part->payload, to_copy);
                state->bytes_received += to_copy;
                state->total_length = rpc_msg_part->payload_length;
                if (state->bytes_received < state->total_length) {
                    state->pending_state = StringTransmit;
                } else {
                    recv_string_cb(lc, state->string);
                    state->pending_state = EmptyState;
                    free(state->string);        // TODO discuss
                }
                break;
            }
            default: break;
        }
    } else if (state->pending_state == StringTransmit) {

    }

    uint64_t num;
    memcpy(&num, rpc_msg_part->payload, sizeof(num));
    rpc->init_state.recv_number_cb(num);
}

static void open_recv_cb(void *arg)
{
    errval_t err;

    debug_printf("open_recv_cb()\n");

    struct lmp_chan *lc = (struct lmp_chan *) arg;

    struct capref client_cap;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    err = lmp_chan_recv(lc, &msg, &client_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_chan_recv()");
        return;
    }

    // In case no capability was sent, return.
    if (capref_is_null(client_cap)) {
        debug_printf("open_recv_cb() could not retrieve a capability.");
        return;
    }

    struct lmp_chan *service_chan = malloc(sizeof(struct lmp_chan));
    lmp_chan_init(service_chan);
    service_chan->local_cap = service_ep;
    service_chan->remote_cap = client_cap;
    service_chan->endpoint = service_lmp_ep;

    // We want the channel to be registered persistently.
    service_chan->send_waitset.persistent = true;

    // TODO: Initialize struct aos_rpc.
    // TODO: Use custom waitset?

    struct callback_state *state = malloc(sizeof(struct callback_state));
    // todo memset
    state->rpc.lc = service_chan;
    state->pending_state = EmptyState;

    err = lmp_chan_register_recv(service_chan, get_default_waitset(), MKCLOSURE(service_recv_cb, state));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_chan_register_recv()");
        return;
    }

    err = lmp_chan_send0(service_chan, LMP_SEND_FLAGS_DEFAULT, service_ep);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_chan_send0()");
        return;
    }
}

static errval_t initserver_setup_open_channel(void)
{
    errval_t err;

    // We want the channel to be registered persistently.
    open_lc.send_waitset.persistent = true;

    err = lmp_chan_accept(&open_lc, DEFAULT_LMP_BUF_WORDS, NULL_CAP);
    // TODO: Handle error.

    err = lmp_chan_alloc_recv_slot(&open_lc);
    // TODO: Handle error.

    open_ep = open_lc.local_cap;

    err = cap_copy(cap_chan_init, open_ep);
    if (err_is_fail(err)) {
        debug_printf("cap_copy() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CAP_COPY);
    }

    err = lmp_chan_register_recv(&open_lc, get_default_waitset(), MKCLOSURE(open_recv_cb, &open_lc));
    // TODO: Handle error.

    return SYS_ERR_OK;
}

errval_t initserver_init(recv_number_callback_t new_recv_number_cb, recv_string_callback_t new_recv_string_cb)
{
    errval_t err;

    recv_number_cb = new_recv_number_cb;
    recv_string_cb = new_recv_string_cb;

    err = endpoint_create(DEFAULT_LMP_BUF_WORDS, &service_ep, &service_lmp_ep);
    if (err_is_fail(err)) {
        debug_printf("endpoint_create() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_ENDPOINT_CREATE);
    }

    err = initserver_setup_open_channel();
    if (err_is_fail(err)) {
        debug_printf("initserver_setup_open_channel() failed: %s\n", err_getstring(err));
        return err;
    }

    return SYS_ERR_OK;
}
