#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/aos_rpc_lmp_marshal.h>

static
void client_response_cb(void *arg) {
    struct aos_rpc *rpc = (struct aos_rpc *) arg;
    struct lmp_chan *lc = &rpc->lc;
    struct aos_rpc_lmp *lmp = rpc->lmp;
    struct client_response_state *state = (struct client_response_state*) lmp->shared;
    struct capref cap;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    errval_t err = lmp_chan_recv(lc, &msg, &cap);
    if (err_is_fail(err) && lmp_err_is_transient(err)) { // reregister
        err = lmp_chan_register_recv(lc, &lmp->ws, MKCLOSURE(client_response_cb, arg));
        if (err_is_fail(err)) {
            lmp->err = LIB_ERR_CHAN_REGISTER_RECV;
            goto clean_up;
        }
    } else if (err_is_fail(err)) {
        lmp->err = err;
        goto clean_up;
    }
    if (state->pending_state == InvalidState) {
        goto clean_up;
    }
    if (state->pending_state == EmptyState) {
        if (state->validate_recv_msg != NULL) {
            err = state->validate_recv_msg(&msg, EmptyState);
        }
        if (err_is_fail(err)) {
            lmp->err = err;
            state->pending_state = InvalidState;
            goto clean_up;
        }
        struct rpc_message_part *msg_part = (struct rpc_message_part *) msg.words;
        state->total_length = msg_part->payload_length; // TODO: introduce max len
        state->bytes_received = 0;
        debug_printf("msg_part->payload_length: %d\n", msg_part->payload_length);

        state->message = malloc(state->total_length + sizeof(struct rpc_message));
        if (state->message == NULL) {
            lmp->err = LIB_ERR_MALLOC_FAIL;
            state->pending_state = InvalidState;
            goto clean_up;
        }

        // copy header
        state->message->msg.method = msg_part->method;
        state->message->msg.status = msg_part->status;
        state->message->msg.payload_length = msg_part->payload_length;
        state->message->cap = cap;
        debug_printf("assign: state->message->msg.payload_length  %d\n", state->message->msg.payload_length);

        // copy payload
        uint64_t to_copy = MIN(MAX_RPC_MSG_PART_PAYLOAD, msg_part->payload_length);
        memcpy(&state->message->msg.payload, msg_part->payload, to_copy);
        state->bytes_received += to_copy;

    } else if (state->pending_state == DataInTransmit) {
        uint64_t to_copy = MIN(LMP_MSG_LENGTH * sizeof(uint64_t), state->total_length - state->bytes_received);
        memcpy(((char *) state->message->msg.payload) + state->bytes_received, (char *) &msg.words[0], to_copy);
        state->bytes_received += to_copy;
    }


    if (state->bytes_received < state->total_length) {
        state->pending_state = DataInTransmit;

        // reregister for rest of message
        err = lmp_chan_register_recv(lc, &lmp->ws, MKCLOSURE(client_response_cb, arg));
        if (err_is_fail(err)) {
            lmp->err = LIB_ERR_CHAN_REGISTER_RECV;
            goto clean_up;
        }
    } else {
        state->pending_state = EmptyState;
        assert(state->total_length == state->bytes_received);
        assert(state->message != NULL);
        debug_printf("state->message->msg.payload_length  %d\n", state->message->msg.payload_length);
    }
    lmp->err = SYS_ERR_OK;
    return;

    clean_up:
    if (state->message != NULL) {
        free(state->message);
    }
    return;

}

errval_t
aos_rpc_lmp_send_and_wait_recv(struct aos_rpc *rpc, struct rpc_message *send, struct rpc_message **recv, validate_recv_msg_t validate_cb)
{
    errval_t err;
    assert(rpc->lmp->shared != NULL);
    struct aos_rpc_lmp *lmp = (struct aos_rpc_lmp *) rpc->lmp;
    struct client_response_state *state = lmp->shared;
    memset(state, 0, sizeof(struct client_response_state));

    lmp->err = SYS_ERR_OK;
    state->pending_state = EmptyState;
    state->validate_recv_msg = validate_cb;

    // register response handler
    err = lmp_chan_register_recv(&rpc->lc, &lmp->ws, MKCLOSURE(client_response_cb, rpc));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_chan_register_recv failed");
        goto clean_up;
    }

    // send request
    err = aos_rpc_lmp_send_message(&rpc->lc, send, LMP_SEND_FLAGS_DEFAULT);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_send_message failed\n");
        goto clean_up;
    }

    // wait until whole message received
    do {
        err = event_dispatch(&lmp->ws);
    } while (err_is_ok(err) && state->pending_state == DataInTransmit);
    if (err_is_fail(err)) {
        goto clean_up;
    }
    if (err_is_fail(lmp->err)) {
        err = lmp->err;
        goto clean_up;
    }
    if (state->pending_state == InvalidState) {
        err = LIB_ERR_LMP_INVALID_RESPONSE;
        goto clean_up;
    }

    // TODO: more input sanitation
    state = lmp->shared;

    assert(state != NULL);
    assert(state->message != NULL);
    assert(recv != NULL);


    debug_printf("state->message->msg.payload_length: %d\n", state->message->msg.payload_length);
    *recv = malloc(sizeof(struct rpc_message) + state->message->msg.payload_length);
    if (*recv == NULL) {
        err = LIB_ERR_MALLOC_FAIL;
        goto clean_up;
    }

    state = lmp->shared;
    memcpy(*recv, state->message, sizeof(struct rpc_message) + state->message->msg.payload_length);

    err = SYS_ERR_OK;
    goto clean_up;

    clean_up:
    if (state->message != NULL) {
        free(state->message);
    }
    return err;
}


errval_t
aos_rpc_lmp_send_message(struct lmp_chan *c, struct rpc_message *msg, lmp_send_flags_t flags)
{
    errval_t err;

    const uint64_t msg_size = sizeof(msg->msg) + msg->msg.payload_length;
    DEBUG_PRINTF("msg size: %d\n", msg_size);

    uintptr_t words[LMP_MSG_LENGTH];

    uint32_t size_sent = 0;
    uint8_t *base = (uint8_t *) &msg->msg;
    bool first = true;

    while(size_sent < msg_size) {
        uint64_t to_send = MIN(sizeof(words), msg_size - size_sent);
        memset(words, 0, sizeof(words));
        memcpy(words, base + size_sent, to_send);

        err = lmp_chan_send4(c, flags, (first ? msg->cap : NULL_CAP), words[0], words[1], words[2], words[3]);

        if (lmp_err_is_transient(err)) {
            DEBUG_ERR(err, "lmp_chan_send4 failed (transient)");
            continue;
        } else if (err_is_fail(err)) {
            DEBUG_ERR(err, "lmp_chan_send4 failed");
            return err;
        }
        size_sent += to_send;
        first = false;
    }
    return SYS_ERR_OK;
}