#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

#include <rpc/server/lmp.h>

#include "initserver.h"

static struct rpc_lmp_server server;

static recv_number_callback_t recv_number_cb = NULL;
static recv_string_callback_t recv_string_cb = NULL;

static void service_recv_cb(void *arg)
{
    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    struct aos_rpc *rpc = &common_state->rpc;
    struct lmp_chan *lc = &rpc->lc;
    struct initserver_cb_state *state = common_state->shared;

    // accumulate message until full message was transmitted
    // check which message type was sent -> call corresponding callback
    // check if callback is null
    struct capref cap;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

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

                if (recv_number_cb != NULL) {
                    recv_number_cb(lc, num);
                }

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
                    if (recv_string_cb != NULL) {
                        recv_string_cb(lc, state->string);
                    }

                    state->pending_state = EmptyState;
                    state->bytes_received = 0;
                    state->total_length = 0;

                    free(state->string);
                    state->string = NULL;
                }
                break;
            }
            default: break;
        }
    } else if (state->pending_state == StringTransmit) {
        uint64_t to_copy = MIN(LMP_MSG_LENGTH * sizeof(uint64_t), state->total_length - state->bytes_received);
        memcpy(state->string + state->bytes_received, (char *) &msg.words[0], to_copy);
        state->bytes_received += to_copy;
        if (state->bytes_received < state->total_length) {
            state->pending_state = StringTransmit;
        } else {
            if (recv_string_cb != NULL) {
                recv_string_cb(lc, state->string);
            }

            state->pending_state = EmptyState;
            state->bytes_received = 0;
            state->total_length = 0;

            free(state->string);
            state->string = NULL;
        }
    }
}

// Initialize channel-specific data.
static void state_init_cb(void *arg)
{
    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    common_state->shared = malloc(sizeof(struct initserver_cb_state));
    struct initserver_cb_state *state = common_state->shared;

    state->pending_state = EmptyState;
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
