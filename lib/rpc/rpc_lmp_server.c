#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

#include <rpc/server/lmp.h>

static struct capref open_ep;
static struct lmp_chan open_lc;

static struct capref service_ep;
static struct lmp_endpoint *service_lmp_ep;

static service_recv_handler_t service_recv_handler;
static state_init_handler_t state_init_handler;
static state_free_handler_t state_free_handler;

// TODO: When another process terminates, free the associated channel. We
// should also call state_free_handler().

// Call the registered receive handler, if any.
static void service_recv_cb(void *arg)
{
    if (service_recv_handler != NULL) {
        service_recv_handler(arg);
    }
}

// Accept an incoming binding request, and return the new endpoint for service
// requests.
static void open_recv_cb(void *arg)
{
    errval_t err;

    struct lmp_chan *open_chan = (struct lmp_chan *) arg;

    struct capref client_cap;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    err = lmp_chan_recv(open_chan, &msg, &client_cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_chan_recv()");
        return;
    }

    // In case no capability was sent, return.
    if (capref_is_null(client_cap)) {
        debug_printf("open_recvcb() could not retrieve a capability.");
        return;
    }

    struct rpc_lmp_handler_state *state = malloc(sizeof(struct rpc_lmp_handler_state));

    err = aos_rpc_lmp_init(&state->rpc);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_lmp_init() failed: %s\n", err_getstring(err));
        return;
    }

    struct lmp_chan *service_chan = &state->rpc.lc;

    service_chan->local_cap = service_ep;
    service_chan->endpoint = service_lmp_ep;

    // We want the channel to be registered persistently.
    service_chan->send_waitset.persistent = true;

    // We have to allocate a new slot, since the current slot may be used for
    // other transmissions.
    err = slot_alloc(&service_chan->remote_cap);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc() failed: %s\n", err_getstring(err));
        return;
    }

    err = cap_copy(service_chan->remote_cap, client_cap);
    if (err_is_fail(err)) {
        debug_printf("cap_copy() failed: %s\n", err_getstring(err));
        return;
    }

    if (state_init_handler != NULL) {
        state_init_handler(state);
    }

    err = lmp_chan_register_recv(service_chan, get_default_waitset(), MKCLOSURE(service_recv_cb, state));
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_register_recv() failed: %s\n", err_getstring(err));
        return;
    }

    err = lmp_chan_send0(service_chan, LMP_SEND_FLAGS_DEFAULT, service_ep);
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_send0() failed: %s\n", err_getstring(err));
        return;
    }
}

// Initialize the channel that accepts incoming binding requests.
static errval_t rpc_lmp_server_setup_open_channel(void)
{
    errval_t err;

    // We want the channel to be registered persistently.
    open_lc.send_waitset.persistent = true;

    err = lmp_chan_accept(&open_lc, DEFAULT_LMP_BUF_WORDS, NULL_CAP);
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_accept() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_LMP_CHAN_ACCEPT);
    }

    err = lmp_chan_alloc_recv_slot(&open_lc);
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_alloc_recv_slot() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_LMP_ALLOC_RECV_SLOT);
    }

    open_ep = open_lc.local_cap;

    err = cap_copy(cap_chan_init, open_ep);
    if (err_is_fail(err)) {
        debug_printf("cap_copy() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CAP_COPY);
    }

    err = lmp_chan_register_recv(&open_lc, get_default_waitset(), MKCLOSURE(open_recv_cb, &open_lc));
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_register_recv() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_LMP_CHAN_RECV);
    }

    return SYS_ERR_OK;
}

// Initialize the server.
errval_t rpc_lmp_server_init(
    service_recv_handler_t new_service_recv_handler,
    state_init_handler_t new_state_init_handler,
    state_free_handler_t new_state_free_handler
)
{
    errval_t err;

    service_recv_handler = new_service_recv_handler;
    state_init_handler = new_state_init_handler;
    state_free_handler = new_state_free_handler;

    err = endpoint_create(DEFAULT_LMP_BUF_WORDS, &service_ep, &service_lmp_ep);
    if (err_is_fail(err)) {
        debug_printf("endpoint_create() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_ENDPOINT_CREATE);
    }

    err = rpc_lmp_server_setup_open_channel();
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_setup_open_channel() failed: %s\n", err_getstring(err));
        return err;
    }

    return SYS_ERR_OK;
}
