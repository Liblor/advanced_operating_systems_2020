#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump_marshal.h>
#include <aos/debug.h>

errval_t aos_rpc_ump_init(struct aos_rpc *rpc, struct capref tx_frame_cap, struct capref rx_frame_cap)
{
    assert(rpc != NULL);

    struct paging_state *state = get_current_paging_state();
    assert(state != NULL);

    void *tx_vaddr;

    err = paging_map_frame(
        state,
        &tx_vaddr,
        BASE_PAGE_SIZE,
        tx_frame_cap,
        NULL,
        NULL
    );
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }

    void *rx_vaddr;

    err = paging_map_frame(
        state,
        &rx_vaddr,
        BASE_PAGE_SIZE,
        rx_frame_cap,
        NULL,
        NULL
    );
    if (err_is_fail(err)) {
        // TODO: Unmap tx_frame_cap.
        debug_printf("paging_map_frame() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }

    // Write mapped addresses into struct aos_rpc.
    rpc->ump.tx_shared_mem = tx_vaddr;
    rpc->ump.rx_shared_mem = rx_vaddr;

    return SYS_ERR_OK;
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
