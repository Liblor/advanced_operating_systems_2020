#ifndef _LIB_RPC_RPC_LMP_SERVER_H_
#define _LIB_RPC_RPC_LMP_SERVER_H_

#include <aos/aos_rpc.h>

typedef void (* service_recv_handler_t)(void *arg);
typedef void (* state_init_handler_t)(void *arg);
typedef void (* state_free_handler_t)(void *arg);

struct rpc_lmp_server {
    struct capref open_ep;
    struct lmp_chan open_lc;

    struct capref service_ep;
    struct lmp_endpoint *service_lmp_ep;

    service_recv_handler_t service_recv_handler;
    state_init_handler_t state_init_handler;
    state_free_handler_t state_free_handler;
};

struct rpc_lmp_handler_state {
    struct aos_rpc rpc;
    struct rpc_lmp_server *server;
    void *shared;
};

errval_t rpc_lmp_server_init(
    struct rpc_lmp_server *server,
    struct capref cap_chan,
    service_recv_handler_t service_recv_handler,
    state_init_handler_t state_init_handler,
    state_free_handler_t state_free_handler
);

#endif
