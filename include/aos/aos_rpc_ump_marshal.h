#ifndef _LIB_RPC_RPC_UMP_CLIENT_H_
#define _LIB_RPC_RPC_UMP_CLIENT_H_

#include <aos/aos_rpc.h>

/// Callback to validate incoming server response
typedef errval_t (*validate_recv_msg_t )(struct ump_recv_msg *msg, enum pending_state state);

enum ump_status {
    UmpEmpty,
    UmpNewMessage,
    UmpNewSegment,
};

enum ump_msg_type {
    BootInfo,
    SpawnRequest,
    SpawnResponse
};

struct frame_cap_info {
    uint64_t base;
    uint64_t size;
}

struct ump_shared_mem {
    enum ump_status status;

    union {
        struct frame_cap_info forge_info;
        uintptr_t words[4];
    };
};

struct aos_rpc_ump {
    struct ump_shared_mem *shared_mem; ///< Pointer to shared memory region
}

/// rpc/ump response state to track and buffer transmission
struct client_response_state {
    struct aos_rpc *rpc;                       ///< common rpc struct
    struct waitset ws;                         ///< waitset used to wait for receive msgs
    errval_t err;                              ///< error to communicate error in receive callback
    uint32_t bytes_received;                   ///< How much was read from the client already.
    uint32_t total_length;                     ///< total bytes to transmit
    enum pending_state pending_state;          ///< transmission state
    validate_recv_msg_t validate_recv_msg;     ///< callback to verify response
    struct rpc_message *message;               ///< response to build/buffer
};

errval_t aos_rpc_ump_send_and_wait_recv_one_no_alloc(
    struct aos_rpc *rpc,
    struct rpc_message *send,
    struct rpc_message *recv,
    validate_recv_msg_t validate_cb,
    struct capref cap
);

/**
 * \brief Marshall rpc_message and wait for a response
 */
errval_t
aos_rpc_ump_send_and_wait_recv(struct aos_rpc *rpc, struct rpc_message *send,
                               struct rpc_message **recv, validate_recv_msg_t validate_cb);

/**
 * \brief Marshall rpc_message and send with UMP
 */
errval_t
aos_rpc_ump_send_message(struct aos_rpc *rpc, struct rpc_message *msg, ump_send_flags_t flags);

#endif
