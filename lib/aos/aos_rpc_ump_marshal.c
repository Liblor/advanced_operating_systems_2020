#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump_marshal.h>
#include <aos/debug.h>

errval_t aos_rpc_ump_init(struct aos_rpc *rpc, struct capref frame_cap)
{
    // TODO Map frame
    // TODO Write mapped address into aos_rpc
}

errval_t aos_rpc_ump_poll(struct aos_rpc *rpc)
{
    thread_mutex_lock_nested(&rpc->mutex);
    // TODO Check status
    switch (rpc->ump.shared_mem->status == ) {
    case UmpEmpty:
        break;
    case UmpNewMessage:
        // TODO Receive new message
        break;
    case UmpNewSegment:
        // TODO Error
        break;
    default:
        break;
    }
    // TODO If new message, start receiving segments
    // TODO Call callback once entire message has been received

    thread_mutex_unlock(&rpc->mutex);
}

errval_t aos_rpc_ump_send_and_wait_recv(
    struct aos_rpc *rpc,
    struct rpc_message *send,
    struct rpc_message **recv,
    validate_recv_msg_t validate_cb
)
{
}

errval_t aos_rpc_ump_send_message(
    struct aos_rpc *rpc,
    struct rpc_message *msg
)
{
}
