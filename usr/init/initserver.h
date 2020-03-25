#ifndef _USR_INIT_INITSERVER_H_
#define _USR_INIT_INITSERVER_H_

#include <aos/aos_rpc.h>

typedef errval_t (*aos_rpc_lmp_recv_number_callback_t)(uintptr_t num);

typedef errval_t (*aos_rpc_lmp_recv_string_callback_t)(char *string);

// Client-specific state.
struct callback_state {
    struct aos_rpc rpc;
    uint32_t count; ///< How much was read from the client already.
};

errval_t initserver_init(aos_rpc_lmp_recv_number_callback_t new_recv_number_cb, aos_rpc_lmp_recv_string_callback_t new_recv_string_cb);

#endif
