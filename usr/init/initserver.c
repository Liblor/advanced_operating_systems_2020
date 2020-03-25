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
    state->lp = service_chan;

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
