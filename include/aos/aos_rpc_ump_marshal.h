#ifndef _LIB_RPC_RPC_UMP_CLIENT_H_
#define _LIB_RPC_RPC_UMP_CLIENT_H_

#include <aos/aos_rpc.h>

/// Callback to validate incoming server response
typedef errval_t (*validate_recv_msg_t )(struct ump_recv_msg *msg, enum pending_state state);

#define UMP_SEGMENT_SIZE (sizeof(uintptr_t) * 4) // 4 words
#define CACHE_LINE_WORDS (8)
#define RING_BUFFER_SLOTS ((uint64_t) (BASE_PAGE_SIZE / (sizeof(uintptr_t) * CACHE_LINE_WORDS))

// Represents one slot in the ring buffer. One slot fits exactly into a cache line.
struct ump_message {
    uintptr_t data[LMP_MSG_LENGTH];
    uintptr_t cap_base;
    uintptr_t cap_size;
    uintptr_t padding[CACHE_LINE_WORDS - 3 - LMP_MSG_LENGTH];
    uintptr_t used; ///< Last word in cache line indicates whether the slot is currently occupied by data
}

struct ump_shared_mem {
    // TODO Is this volatile correct?
    volatile struct ump_message slots[RING_BUFFER_SLOTS];
};

struct aos_rpc_ump {
    struct ump_shared_mem *tx_shared_mem; ///< Shared memory region to send
    uint64_t tx_slot_next; ///< Next slot to write into

    struct ump_shared_mem *rx_shared_mem; ///< Shared memory region to receive
    uint64_t rx_slot_next; ///< Next slot to read from
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
