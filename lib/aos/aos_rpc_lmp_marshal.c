#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/aos_rpc_lmp_marshal.h>
#include <aos/debug.h>

static void
client_response_cb(void *arg) {
    struct aos_rpc *rpc = (struct aos_rpc *) arg;
    struct lmp_chan *lc = &rpc->lc;
    struct aos_rpc_lmp *lmp = rpc->lmp;
    struct client_response_state *state = (struct client_response_state*) lmp->shared;
    struct capref cap = NULL_CAP;
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

        state->message = malloc(state->total_length + sizeof(struct rpc_message));
        if (state->message == NULL) {
            lmp->err = LIB_ERR_MALLOC_FAIL;
            state->pending_state = InvalidState;
            goto clean_up;
        }

        // copy heoader
        state->message->msg.method = msg_part->method;
        state->message->msg.status = msg_part->status;
        state->message->msg.payload_length = msg_part->payload_length;
        state->message->cap = cap;

        // copy payload
        uint64_t to_copy = MIN(MAX_RPC_MSG_PART_PAYLOAD, msg_part->payload_length);
        memcpy(state->message->msg.payload, msg_part->payload, to_copy);
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
    }
    lmp->err = SYS_ERR_OK;
    goto clean_up;

    clean_up:
    return;
}

errval_t
aos_rpc_lmp_send_and_wait_recv(struct aos_rpc *rpc, struct rpc_message *send,
        struct rpc_message **recv, validate_recv_msg_t validate_cb)
{
    errval_t err;
    assert(rpc->lmp->shared != NULL);
    struct aos_rpc_lmp *lmp = (struct aos_rpc_lmp *) rpc->lmp;
    struct client_response_state *state = lmp->shared;

    memset(state, 0, sizeof(struct client_response_state));
    state->pending_state = EmptyState;
    state->validate_recv_msg = validate_cb;
    lmp->err = SYS_ERR_OK;

    err = lmp_chan_register_recv(&rpc->lc, &lmp->ws, MKCLOSURE(client_response_cb, rpc));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_chan_register_recv failed");
        goto clean_up;
    }

    // allocate recv slot in case we get a cap in result
    // need to free again if not used
    err = lmp_chan_alloc_recv_slot(&rpc->lc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "can not allocate new slot for recv cap\n");
        goto clean_up;
    }

    err = aos_rpc_lmp_send_message(&rpc->lc, send, LMP_SEND_FLAGS_DEFAULT);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_send_message failed\n");
        goto clean_up;
    }

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

    assert(state != NULL);
    assert(state->message != NULL);
    assert(recv != NULL);

    *recv = malloc(sizeof(struct rpc_message) + state->message->msg.payload_length);
    if (*recv == NULL) {
        err = LIB_ERR_MALLOC_FAIL;
        goto clean_up;
    }

    // TODO: more input sanitation
    state = lmp->shared;
    memcpy(*recv, state->message, sizeof(struct rpc_message) + state->message->msg.payload_length);


    err = SYS_ERR_OK;
    goto clean_up;

    clean_up:
    // free slot in case no cap was received
    if (*recv != NULL) {
        if (capref_is_null((*recv)->cap)) {
            slot_free(rpc->lc.endpoint->recv_slot);
        }
    }
    free(state->message);
    state->message = NULL;
    return err;
}

errval_t
aos_rpc_lmp_send_message(struct lmp_chan *c, struct rpc_message *msg, lmp_send_flags_t flags)
{
    errval_t err;
    const uint64_t msg_size = sizeof(struct rpc_message_part) + msg->msg.payload_length;

    uintptr_t words[LMP_MSG_LENGTH];
    uint32_t size_sent = 0;
    uint8_t *base = (uint8_t *) &msg->msg;
    bool first = true;

    uint64_t retries = 0;
    err = SYS_ERR_OK;

    while(size_sent < msg_size && retries <= TRANSIENT_ERR_RETRIES) {
        uint64_t to_send = MIN(sizeof(words), msg_size - size_sent);
        memset(words, 0, sizeof(words));
        memcpy(words, base + size_sent, to_send);

        err = lmp_chan_send4(c, flags, (first ? msg->cap : NULL_CAP), words[0], words[1], words[2], words[3]);

        if (lmp_err_is_transient(err)) {
            DEBUG_ERR(err, "lmp_chan_send4 failed (transient): %s\n", err_getstring(err));
            retries++;
            continue;

        } else if (err_is_fail(err)) {
            DEBUG_ERR(err, "lmp_chan_send4 failed");
            return err;
        }
        size_sent += to_send;
        first = false;
    }
    return err;
}