#ifndef _LIB_RPC_RPC_LMP_CLIENT_H_
#define _LIB_RPC_RPC_LMP_CLIENT_H_

#include <aos/aos_rpc.h>

#define return_err_trace(cond, msg) do { \
        if (cond) { \
            DEBUG_ERR(LIB_ERR_LMP_INVALID_RESPONSE, msg); \
            return LIB_ERR_LMP_INVALID_RESPONSE;  \
        } \
    } while(0);

#define return_err_no_trace(cond, msg) do { \
        if (cond) { \
            return LIB_ERR_LMP_INVALID_RESPONSE;  \
        } \
    } while(0);

#define return_err(cond, msg) return_err_no_trace(cond,msg)

/// Callback to validate incoming server response
typedef errval_t (*validate_recv_msg_t )(struct lmp_recv_msg *msg, enum pending_state state);

/// rpc/lmp response state to track and buffer transmission

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

errval_t aos_rpc_lmp_send_and_wait_recv_one_no_alloc(
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
aos_rpc_lmp_send_and_wait_recv(struct aos_rpc *rpc, struct rpc_message *send,
                               struct rpc_message **recv, validate_recv_msg_t validate_cb);

/**
 * \brief Marshall rpc_message and send with LMP
 */
errval_t
aos_rpc_lmp_send_message(struct aos_rpc *rpc, struct rpc_message *msg, lmp_send_flags_t flags);

#endif
