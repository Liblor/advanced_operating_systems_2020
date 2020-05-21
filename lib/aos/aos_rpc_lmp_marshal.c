#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/aos_rpc_lmp_marshal.h>
#include <aos/debug.h>

static void
client_response_cb(void *arg)
{
    struct client_response_state *state = (struct client_response_state *) arg;
    struct aos_rpc *rpc = (struct aos_rpc *) state->rpc;
    struct lmp_chan *lc = &rpc->lmp.chan;

    struct capref cap = NULL_CAP;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    errval_t err = lmp_chan_recv(lc, &msg, &cap);

    if (err_is_fail(err) && lmp_err_is_transient(err)) { // reregister
        err = lmp_chan_register_recv(lc, &state->ws, MKCLOSURE(client_response_cb, arg));
        if (err_is_fail(err)) {
            state->err = LIB_ERR_CHAN_REGISTER_RECV;
            goto clean_up;
        }
    } else if (err_is_fail(err)) {
        state->err = err;
        goto clean_up;
    }

    if (state->pending_state == InvalidState) {
        state->err = LIB_ERR_LMP_INVALID_RESPONSE;
        goto clean_up;
    }
    if (state->pending_state == EmptyState) {
        if (state->validate_recv_msg != NULL) {
            err = state->validate_recv_msg(&msg, EmptyState);
        }
        if (err_is_fail(err)) {
            state->err = err;
            state->pending_state = InvalidState;
            goto clean_up;
        }

        struct rpc_message_part *msg_part = (struct rpc_message_part *) msg.words;
        state->total_length = msg_part->payload_length; // TODO: introduce max len
        state->bytes_received = 0;

        state->message = malloc(state->total_length + sizeof(struct rpc_message));
        if (state->message == NULL) {
            state->err = LIB_ERR_MALLOC_FAIL;
            state->pending_state = InvalidState;
            goto clean_up;
        }

        // copy header
        state->message->msg.method = msg_part->method;
        state->message->msg.status = msg_part->status;
        state->message->msg.payload_length = msg_part->payload_length;
        state->message->cap = cap;

        // copy payload
        const uint64_t to_copy = MIN(MAX_RPC_MSG_PART_PAYLOAD, msg_part->payload_length);
        memcpy(state->message->msg.payload, msg_part->payload, to_copy);
        state->bytes_received += to_copy;

    } else if (state->pending_state == DataInTransmit) {
        const uint64_t to_copy = MIN(LMP_MSG_LENGTH * sizeof(uint64_t),
                               state->total_length - state->bytes_received);
        memcpy(((char *) state->message->msg.payload) + state->bytes_received,
               (char *) &msg.words[0], to_copy);
        state->bytes_received += to_copy;
    }
    if (state->bytes_received < state->total_length) {
        state->pending_state = DataInTransmit;

        // reregister for rest of message
        err = lmp_chan_register_recv(lc, &state->ws, MKCLOSURE(client_response_cb, arg));
        if (err_is_fail(err)) {
            state->err = LIB_ERR_CHAN_REGISTER_RECV;
            goto clean_up;
        }
    } else {
        state->pending_state = EmptyState;
        assert(state->total_length == state->bytes_received);
        assert(state->message != NULL);
    }
    state->err = SYS_ERR_OK;
    goto clean_up;

    clean_up:
    return;
}

static void
client_response_cb_one_no_alloc(void *arg)
{
    struct client_response_state *state = (struct client_response_state *) arg;
    struct aos_rpc *rpc = (struct aos_rpc *) state->rpc;
    struct lmp_chan *lc = &rpc->lmp.chan;

    struct capref cap = NULL_CAP;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    errval_t err = lmp_chan_recv(lc, &msg, &cap);

    if (err_is_fail(err) && lmp_err_is_transient(err)) { // reregister
        err = lmp_chan_register_recv(lc, &state->ws, MKCLOSURE(client_response_cb_one_no_alloc, arg));
        if (err_is_fail(err)) {
            state->err = LIB_ERR_CHAN_REGISTER_RECV;
            goto clean_up;
        }
    } else if (err_is_fail(err)) {
        state->err = err;
        goto clean_up;
    }

    if (state->pending_state == EmptyState) {
        if (state->validate_recv_msg != NULL) {
            err = state->validate_recv_msg(&msg, EmptyState);
            if (err_is_fail(err)) {
                state->err = err;
                state->pending_state = InvalidState;
                goto clean_up;
            }
        }

        struct rpc_message_part *msg_part = (struct rpc_message_part *) msg.words;
        state->total_length = msg_part->payload_length; // TODO: introduce max len
        state->bytes_received = 0;

        // copy header
        state->message->msg.method = msg_part->method;
        state->message->msg.status = msg_part->status;
        state->message->msg.payload_length = msg_part->payload_length;
        state->message->cap = cap;

        // copy payload
        const uint64_t to_copy = MIN(MAX_RPC_MSG_PART_PAYLOAD, msg_part->payload_length);
        memcpy(state->message->msg.payload, msg_part->payload, to_copy);
        state->bytes_received += to_copy;
    }
    if (state->bytes_received < state->total_length) {
        assert(false);
    } else {
        state->pending_state = EmptyState;
        assert(state->total_length == state->bytes_received);
        assert(state->message != NULL);
    }
    state->err = SYS_ERR_OK;
    goto clean_up;

    clean_up:
    return;
}

// Receive just a single packet, and do not allocate any dynamic memory.
errval_t aos_rpc_lmp_send_and_wait_recv_one_no_alloc(
    struct aos_rpc *rpc,
    struct rpc_message *send,
    struct rpc_message *recv,
    validate_recv_msg_t validate_cb,
    struct capref ret_cap
)
{
    errval_t err;

    assert(rpc != NULL);
    assert(rpc->type == RpcTypeLmp);
    assert(send != NULL);
    assert(recv != NULL);

    struct client_response_state state;
    memset(&state, 0, sizeof(struct client_response_state));

    waitset_init(&state.ws);
    state.err = SYS_ERR_OK;
    state.rpc = rpc;
    state.pending_state = EmptyState;
    state.validate_recv_msg = validate_cb;
    state.message = recv;

    thread_mutex_lock_nested(&rpc->mutex);

    if (!capref_is_null(ret_cap)) {
        lmp_chan_set_recv_slot(&rpc->lmp.chan, ret_cap);
    }

    // TODO: Use custom callback.
    err = lmp_chan_register_recv(&rpc->lmp.chan, &state.ws, MKCLOSURE(client_response_cb_one_no_alloc, &state));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_chan_register_recv failed");
        goto clean_up;
    }

    err = aos_rpc_lmp_send_message(rpc, send, LMP_SEND_FLAGS_DEFAULT);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_send_message failed\n");
        goto clean_up;
    }

    err = event_dispatch(&state.ws);

    if (err_is_fail(state.err)) {
        err = state.err;
        goto clean_up;
    }
    if (state.pending_state == InvalidState) {
        err = LIB_ERR_LMP_INVALID_RESPONSE;
        goto clean_up;
    }

    assert(state.message != NULL);

    err = SYS_ERR_OK;

clean_up:
    thread_mutex_unlock(&rpc->mutex);
    state.message = NULL;
    waitset_destroy(&state.ws);

    return err;
}

errval_t
aos_rpc_lmp_send_and_wait_recv(struct aos_rpc *rpc, struct rpc_message *send,
                               struct rpc_message **recv, validate_recv_msg_t validate_cb)
{
    errval_t err;

    assert(rpc != NULL);
    assert(rpc->type == RpcTypeLmp);
    assert(send != NULL);

    if (recv != NULL) {
        *recv = NULL;
    }

    struct client_response_state state;
    memset(&state, 0, sizeof(struct client_response_state));

    waitset_init(&state.ws);
    state.err = SYS_ERR_OK;
    state.rpc = rpc;
    state.pending_state = EmptyState;
    state.validate_recv_msg = validate_cb;
    state.message = NULL;

    thread_mutex_lock_nested(&rpc->mutex);

    // allocate recv slot in case we get a cap in result
    // need to free again if not used
    err = lmp_chan_alloc_recv_slot(&rpc->lmp.chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "can not allocate new slot for recv cap\n");
        goto clean_up;
    }

    err = lmp_chan_register_recv(&rpc->lmp.chan, &state.ws, MKCLOSURE(client_response_cb, &state));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_chan_register_recv failed");
        goto clean_up;
    }

    err = aos_rpc_lmp_send_message(rpc, send, LMP_SEND_FLAGS_DEFAULT);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_send_message failed\n");
        goto clean_up;
    }

    do {
        err = event_dispatch(&state.ws);
    } while (err_is_ok(err) && state.pending_state == DataInTransmit);

    if (err_is_fail(err)) {
        goto clean_up;
    }
    if (err_is_fail(state.err)) {
        err = state.err;
        goto clean_up;
    }
    if (state.pending_state == InvalidState) {
        err = LIB_ERR_LMP_INVALID_RESPONSE;
        goto clean_up;
    }

    assert(state.message != NULL);

    if (recv != NULL) {
        *recv = malloc(sizeof(struct rpc_message) + state.message->msg.payload_length);
        if (*recv == NULL) {
            err = LIB_ERR_MALLOC_FAIL;
            goto clean_up;
        }

        memcpy(*recv, state.message, sizeof(struct rpc_message) + state.message->msg.payload_length);
    }

    err = SYS_ERR_OK;

clean_up:
    // free slot in case no cap was received
    if (*recv != NULL) {
        if (capref_is_null((*recv)->cap)) {
            slot_free(rpc->lmp.chan.endpoint->recv_slot);
        }
    }
    thread_mutex_unlock(&rpc->mutex);
    free(state.message);
    state.message = NULL;
    waitset_destroy(&state.ws);

    return err;
}

errval_t
aos_rpc_lmp_send_message(struct aos_rpc *rpc, struct rpc_message *msg, lmp_send_flags_t flags)
{
    errval_t err;

    assert(rpc != NULL);
    assert(rpc->type == RpcTypeLmp);
    assert(msg != NULL);

    const uint64_t msg_size = sizeof(struct rpc_message_part) + msg->msg.payload_length;

    uintptr_t words[LMP_MSG_LENGTH];
    uint32_t size_sent = 0;
    uint8_t *base = (uint8_t *) &msg->msg;
    bool first = true;

    uint64_t retries = 0;
    err = SYS_ERR_OK;

    thread_mutex_lock_nested(&rpc->mutex);

    //    while (size_sent < msg_size && retries < TRANSIENT_ERR_RETRIES) {
while (size_sent < msg_size) {
        uint64_t to_send = MIN(sizeof(words), msg_size - size_sent);
        memset(words, 0, sizeof(words));
        memcpy(words, base + size_sent, to_send);

        err = lmp_chan_send4(&rpc->lmp.chan, flags, (first ? msg->cap : NULL_CAP), words[0], words[1], words[2], words[3]);

        if (lmp_err_is_transient(err)) {
            retries++;
            thread_yield();
            continue;
        } else if (err_is_fail(err)) {
            break;
        }

        size_sent += to_send;
        first = false;
        retries = 0;
    }

    thread_mutex_unlock(&rpc->mutex);

    if (err_is_fail(err)) {
        if (retries >= TRANSIENT_ERR_RETRIES) {
            debug_printf("a transient error occured %u times, retries exceeded\n", retries);
        }

        DEBUG_ERR(err, "lmp_chan_send4 failed");
        return err;
    }

    return err;
}
