#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

#include <rpc/server/lmp.h>

#include "memoryserver.h"

static ram_cap_callback_t ram_cap_cb = NULL;

// Allocate RAM and send it to the client. Also, we notify our dispatcher that
// we allocated RAM.
static void service_recv_cb(void *arg)
{
#if 0
    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    struct aos_rpc *rpc = &common_state->rpc;
    struct lmp_chan *lc = &rpc->lc;
    struct memoryserver_cb_state *state = common_state->shared;

    if (ram_cap_cb != NULL) {
        ram_cap_cb();
    }
#endif
}

// Initialize channel-specific data.
static void state_init_cb(void *arg)
{
#if 0
    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    common_state->shared = malloc(sizeof(struct memoryserver_cb_state));
    struct memoryserver_cb_state *state = common_state->shared;
#endif
}

// Free channel-specific data.
static void state_free_cb(void *arg)
{
}

errval_t memoryserver_init(ram_cap_callback_t new_ram_cap_cb)
{
    errval_t err;

    ram_cap_cb = new_ram_cap_cb;

    err = rpc_lmp_server_init(cap_chan_memory, service_recv_cb, state_init_cb, state_free_cb);
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
