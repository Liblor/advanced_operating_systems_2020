#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

#include <rpc/server/lmp.h>

#include "serialserver.h"

static struct rpc_lmp_server server;

static putchar_callback_t putchar_cb = NULL;
static getchar_callback_t getchar_cb = NULL;

static void service_recv_cb(void *arg)
{
#if 0
    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    struct aos_rpc *rpc = &common_state->rpc;
    struct lmp_chan *lc = &rpc->lc;
    struct serialserver_cb_state *state = common_state->shared;
#endif
}

// Initialize channel-specific data.
static void state_init_cb(void *arg)
{
#if 0
    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    common_state->shared = malloc(sizeof(struct serialserver_cb_state));
    struct serialserver_cb_state *state = common_state->shared;
#endif
}

// Free channel-specific data.
static void state_free_cb(void *arg)
{
}

errval_t serialserver_init(
    putchar_callback_t new_putchar_cb,
    getchar_callback_t new_getchar_cb
)
{
    errval_t err;

    putchar_cb = new_putchar_cb;
    getchar_cb = new_getchar_cb;

    err = rpc_lmp_server_init(&server, cap_chan_serial, service_recv_cb, state_init_cb, state_free_cb);
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
