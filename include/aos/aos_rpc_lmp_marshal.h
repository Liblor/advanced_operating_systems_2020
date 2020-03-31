#ifndef _LIB_RPC_RPC_LMP_CLIENT_H_
#define _LIB_RPC_RPC_LMP_CLIENT_H_

#include <aos/aos_rpc.h>

// TODO: move to header file
typedef errval_t (* validate_recv_msg_t )(struct lmp_recv_msg *msg, enum pending_state state);

struct client_response_state {
    uint32_t bytes_received; ///< How much was read from the client already.
    uint32_t total_length;
    enum pending_state pending_state;
    validate_recv_msg_t validate_recv_msg;
    struct rpc_message *message;
};

errval_t
aos_rpc_lmp_send_and_wait_recv(struct aos_rpc *rpc, struct rpc_message *send, struct rpc_message **recv, validate_recv_msg_t validate_cb);



/**
 * \brief Marshall rpc_message and send with LMP
 */
errval_t aos_rpc_lmp_send_message(struct lmp_chan *c, struct rpc_message *msg, lmp_send_flags_t flags);




#endif
