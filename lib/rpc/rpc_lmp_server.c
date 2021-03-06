#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

#include <rpc/server/lmp.h>

// TODO: When another process terminates, free the associated channel. We
// should also call state_free_handler().

static size_t full_msg_size(struct rpc_message_part msg) {
    size_t header_size = sizeof(struct rpc_message_part);
    return header_size + msg.payload_length;
}

static void add_segment(void *dst_buf, struct lmp_recv_msg segment, size_t bytes_total, size_t *bytes_received) {
    size_t bytes_left = bytes_total - *bytes_received;
    void *dst_ptr = ((void *) dst_buf) + *bytes_received;

    size_t to_copy = MIN(LMP_SEGMENT_SIZE, bytes_left);
    memcpy(dst_ptr, segment.words, to_copy);
    *bytes_received += to_copy;
}

static inline void reset_state(struct rpc_lmp_handler_state *state)
{
    assert(state != NULL);

    state->recv_state = Msg_State_Empty;
    free(state->msg);
}

// Call the registered receive handler, if any.
static void service_recv_cb(void *arg)
{
    errval_t err;

    struct rpc_lmp_handler_state *state = arg;
    struct rpc_lmp_server *server = state->server;
    struct lmp_chan *lc = &state->rpc.lmp.chan;

    // Check if server processing is paused
    if (server->processing_paused) {
        goto reregister;
    }

    // Accumulate message until full message is received
    struct capref cap;
    struct lmp_recv_msg segment = LMP_RECV_MSG_INIT;

    err = lmp_chan_recv(lc, &segment, &cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_chan_recv()");
        reset_state(state);
        goto reregister;
    }

    // TODO Reply with errval_t when an error occurs

    // TODO More message sanity checks
    assert(sizeof(struct rpc_message_part) <= segment.buf.buflen * sizeof(uintptr_t));

    // Allocate new receive capability slot if the last one has been used
    if (!capref_is_null(cap)) {
        err = lmp_chan_alloc_recv_slot(lc);
        if (err_is_fail(err)) {
            debug_printf("lmp_chan_alloc_recv_slot() failed: %s\n", err_getstring(err));
            goto reregister;
        }
    }

    size_t bytes_total;
    struct rpc_message_part *header;

    switch (state->recv_state) {
    case Msg_State_Empty:
        // Assumption is that the length field of the header fits into the first segment of a message.
        header = (struct rpc_message_part *) segment.words;
        bytes_total = full_msg_size(*header);

        if (header->status != Status_Ok) {
            debug_printf("received request where status is not ok\n");
            reset_state(state);
            goto reregister;
        }

        // Allocate memory for the full message
        state->msg = (struct rpc_message *) calloc(1, sizeof(struct rpc_message) + header->payload_length);
        if (state->msg == NULL) {
            debug_printf("calloc() failed\n");
            reset_state(state);
            goto reregister;
        }

        // Some messages include a capability in the first segment
        state->msg->cap = cap;

        // Reset counter for received bytes (header has already been received)
        state->bytes_received = 0;

        // Copy first segment into message buffer
        add_segment(&state->msg->msg, segment, bytes_total, &state->bytes_received);

        state->recv_state = Msg_State_Received_Header;
        break;
    case Msg_State_Received_Header:
        bytes_total = full_msg_size(state->msg->msg);

        // Copy segment into message buffer
        add_segment(&state->msg->msg, segment, bytes_total, &state->bytes_received);
        break;
    default:
        assert(!"Unknown message state");
        break;
    }

    // Check if the full message has been received
    if (state->bytes_received == full_msg_size(state->msg->msg)) {
        if (server->service_recv_handler != NULL) {
            // TODO Also pass a callback here to send a reply message
            server->service_recv_handler(state->msg, state->shared, &state->rpc, server->shared);
        }
        reset_state(state);
    }

    // always reregister callback to continue to receive requests
reregister:
    err = lmp_chan_register_recv(lc, state->server->ws, MKCLOSURE(service_recv_cb, state));
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_register_recv() failed: %s\n", err_getstring(err));
    }
}

// Accept an incoming binding request, and return the new endpoint for service
// requests.
static void open_recv_cb(void *arg)
{
    errval_t err;

    struct rpc_lmp_server *server = arg;

    struct capref client_cap;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    err = lmp_chan_recv(&server->open_lc, &msg, &client_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_chan_recv()");
        goto reregister;
    }

    // In case no capability was sent, return.
    if (capref_is_null(client_cap)) {
        debug_printf("open_recvcb() could not retrieve a capability.\n");
        goto reregister;
    }

    struct rpc_lmp_handler_state *state = calloc(1, sizeof(struct rpc_lmp_handler_state));
    if (state == NULL) {
        debug_printf("calloc() cannot allocate memory.\n");
        goto reregister;
    }

    state->recv_state = Msg_State_Empty;
    state->msg = NULL;

    state->server = server;

    err = aos_rpc_lmp_init(&state->rpc);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_lmp_init() failed: %s\n", err_getstring(err));
        goto reregister;
    }

    struct lmp_chan *service_chan = &state->rpc.lmp.chan;

    err = endpoint_create(DEFAULT_LMP_BUF_WORDS, &service_chan->local_cap, &service_chan->endpoint);
    if (err_is_fail(err)) {
        debug_printf("endpoint_create() failed: %s\n", err_getstring(err));
        goto reregister;
    }

    service_chan->remote_cap = client_cap;

    err = lmp_chan_alloc_recv_slot(&server->open_lc);
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_alloc_recv_slot() failed: %s\n", err_getstring(err));
        goto reregister;
    }

    if (server->state_init_handler != NULL) {
        state->shared = server->state_init_handler(server->shared);
    }

    err = lmp_chan_alloc_recv_slot(service_chan);
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_alloc_recv_slot() failed: %s\n", err_getstring(err));
        goto reregister;
    }

    err = lmp_chan_register_recv(service_chan, state->server->ws, MKCLOSURE(service_recv_cb, state));
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_register_recv() failed: %s\n", err_getstring(err));
        goto reregister;
    }

    uint32_t retries = 0;
    do {
        err = lmp_chan_send0(service_chan, LMP_SEND_FLAGS_DEFAULT, service_chan->local_cap);
        if (lmp_err_is_transient(err)) {
            retries++;
            if (retries >= TRANSIENT_ERR_RETRIES) {
                debug_printf("a transient error occured %u times, retries exceeded\n", retries);
                break;
            }
        }
    } while (lmp_err_is_transient(err));
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_send0() failed: %s\n", err_getstring(err));
        goto reregister;
    }

reregister:
    err = lmp_chan_register_recv(&server->open_lc, server->ws, MKCLOSURE(open_recv_cb, server));
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_register_recv() failed: %s\n", err_getstring(err));
    }
}

// Initialize the channel that accepts incoming binding requests.
static errval_t rpc_lmp_server_setup_open_channel(struct rpc_lmp_server *server, struct capref cap_chan)
{
    errval_t err;

    err = lmp_chan_accept(&server->open_lc, DEFAULT_LMP_BUF_WORDS, NULL_CAP);
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_accept() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_LMP_CHAN_ACCEPT);
    }

    err = lmp_chan_alloc_recv_slot(&server->open_lc);
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_alloc_recv_slot() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
    }

    server->open_ep = server->open_lc.local_cap;

    err = cap_copy(cap_chan, server->open_ep);
    if (err_is_fail(err)) {
        debug_printf("cap_copy() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CAP_COPY);
    }

    err = lmp_chan_register_recv(&server->open_lc, server->ws, MKCLOSURE(open_recv_cb, server));
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_register_recv() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_LMP_CHAN_RECV);
    }

    return SYS_ERR_OK;
}

void rpc_lmp_server_pause_processing(struct rpc_lmp_server *server)
{
    server->processing_paused = true;
}

void rpc_lmp_server_start_processing(struct rpc_lmp_server *server)
{
    server->processing_paused = false;
}

// Initialize the server.
errval_t rpc_lmp_server_init(
    struct rpc_lmp_server *server,
    struct capref cap_chan,
    service_recv_handler_t new_service_recv_handler,
    state_init_handler_t new_state_init_handler,
    state_free_handler_t new_state_free_handler,
    void *server_state,
    struct waitset *ws
)
{
    errval_t err;

    server->service_recv_handler = new_service_recv_handler;
    server->state_init_handler = new_state_init_handler;
    server->state_free_handler = new_state_free_handler;
    server->processing_paused = false;
    server->shared = server_state;

    if (ws == NULL) {
        server->ws = get_default_waitset();
    } else {
        server->ws = ws;
    }

    err = rpc_lmp_server_setup_open_channel(server, cap_chan);
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_setup_open_channel() failed: %s\n", err_getstring(err));
        return err;
    }

    return SYS_ERR_OK;
}
