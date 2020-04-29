#ifndef _LIB_RPC_RPC_UMP_SERVER_H_
#define _LIB_RPC_RPC_UMP_SERVER_H_

#include <aos/aos_rpc.h>

typedef void (* service_recv_handler_t)(struct rpc_message *msg, void *callback_state, struct aos_rpc *rpc, void *server_state);

// Receives the server state.
// Must return the new callback state.
typedef void *(* state_init_handler_t)(void *server_state);

// Receives the server state and the callback state.
// Must free the callback state.
typedef void (* state_free_handler_t)(void *server_state, void *arg);

struct rpc_ump_server {
    collections_listnode *client_list;
    uint64_t client_count;
    uint64_t client_next;

    service_recv_handler_t service_recv_handler;
    state_init_handler_t state_init_handler;
    state_free_handler_t state_free_handler;

    void *shared; ///< The specific implementation can maintain a server state here.
};

errval_t rpc_ump_server_serve_next(struct rpc_ump_server *server);

errval_t rpc_ump_server_add_client(struct rpc_ump_server *server, struct aos_rpc *rpc);

errval_t rpc_ump_server_init(
    struct rpc_ump_server *server,
    service_recv_handler_t new_service_recv_handler,
    state_init_handler_t new_state_init_handler,
    state_free_handler_t new_state_free_handler,
    void *server_state
);

#endif
