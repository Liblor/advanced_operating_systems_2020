#ifndef _LIB_RPC_RPC_LMP_SERVER_H_
#define _LIB_RPC_RPC_LMP_SERVER_H_

#include <aos/aos_rpc.h>

struct rpc_lmp_handler_state {
    struct aos_rpc rpc;
    void *shared;
};

typedef void (* service_recv_handler_t)(void *arg);
typedef void (* state_init_handler_t)(void *arg);
typedef void (* state_free_handler_t)(void *arg);

errval_t rpc_lmp_server_init(
    service_recv_handler_t service_recv_handler,
    state_init_handler_t state_init_handler,
    state_free_handler_t state_free_handler
);

#endif
