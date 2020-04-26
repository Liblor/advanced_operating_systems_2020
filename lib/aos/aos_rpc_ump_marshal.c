#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump_marshal.h>
#include <aos/debug.h>

errval_t aos_rpc_ump_init(
    struct aos_rpc *rpc,
    struct capref *tx_cap
)
{
    errval_t err;

    assert(rpc != NULL);
    assert(tx_cap != NULL);

    err = frame_alloc(tx_cap, BASE_PAGE_SIZE, NULL);
    if (err_is_fail(err)) {
        debug_printf("frame_alloc() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_FRAME_CREATE);
    }

    void *tx_addr = NULL;

    err = paging_map_frame(
        get_current_paging_state(),
        &tx_addr,
        BASE_PAGE_SIZE,
        *tx_cap,
        NULL,
        NULL
    );
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }

    memset(*tx_addr, 0x00, BASE_PAGE_SIZE);

    rpc->ump.tx_shared_mem = tx_addr;

    return SYS_ERR_OK;
}

errval_t aos_rpc_ump_set_rx(
    struct aos_rpc *rpc,
    struct capref rx_frame_cap
)
{
    errval_t err;

    assert(rpc != NULL);

    void *rx_vaddr;

    err = paging_map_frame(
        get_current_paging_state(),
        &rx_vaddr,
        BASE_PAGE_SIZE,
        rx_frame_cap,
        NULL,
        NULL
    );
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }

    rpc->ump.rx_shared_mem = rx_vaddr;

    return SYS_ERR_OK;
}

static bool aos_rpc_ump_can_receive(struct aos_rpc *rpc)
{
    thread_mutex_lock_nested(&rpc->mutex);

    // TODO: Check if the next message can be read.

    thread_mutex_unlock(&rpc->mutex);

    return false;
}

errval_t aos_rpc_ump_receive(struct aos_rpc *rpc, struct rpc_message *message)
{
    assert(message != NULL);

    thread_mutex_lock_nested(&rpc->mutex);

    // TODO: Rececive a full struct rpc_message.

    thread_mutex_unlock(&rpc->mutex);

    return SYS_ERR_OK;
}

errval_t aos_rpc_ump_receive_non_block(struct aos_rpc *rpc, struct rpc_message *message)
{
    errval_t err;

    assert(message != NULL);

    thread_mutex_lock_nested(&rpc->mutex);

    bool can_receive = aos_rpc_ump_can_receive(rpc);

    if (!can_receive) {
        return SYS_ERR_OK;
    }

    err = aos_rpc_ump_receive(rpc, message);
    if (err_is_fail(err)) {
        return err;
    }

    thread_mutex_unlock(&rpc->mutex);

    return SYS_ERR_OK;
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
    errval_t err;

    assert(rpc != NULL);
    assert(msg != NULL);

    uint64_t cap_base = 0;
    uint64_t cap_size = 0;

    if (!capref_is_null(msg->cap)) {
        struct frame_identity fi;

        err = frame_identify(msg->cap, &fi);
        if (err_is_fail(err)) {
            debug_printf("frame_identify() failed: %s\n", err_getstring(err));
            return err;
        }

        cap_base = fi.base;
        cap_size = fi.bytes;
    }

    struct ump_shared_mem *shared_mem = rpc->ump.tx_shared_mem;

    const uint8_t *msg_base = (uint8_t *) &msg->msg;
    const uint64_t msg_size = sizeof(struct rpc_message_part) + msg->msg.payload_length;
    bool first = true;

    thread_mutex_lock_nested(&rpc->mutex);

    // TODO Use barriers
    while (size_sent < msg_size) {
        uint64_t to_send = MIN(UMP_MESSAGE_DATA_SIZE, msg_size - size_sent);
        uint64_t tx_slot = rpc->ump.tx_slot_next;
        struct ump_message *slot = &shared_mem->slots[tx_slot];

        // Wait until the next tx slot is free
        while(slot->used == 1) {
            thread_yield();
        }

        if (first) {
            slot->cap_base = cap_base;
            slot->cap_size = cap_size;
        } else {
            slot->cap_base = 0;
            slot->cap_size = 0;
        }

        memset(slot->data, 0, UMP_MESSAGE_DATA_SIZE);
        memcpy(slot->data, msg_base + size_sent, to_send);

        size_sent += to_send;
        first = false;

        rpc->ump.tx_slot_next++;
        slot->used = 1;
    }

    thread_mutex_unlock(&rpc->mutex);

    return SYS_ERR_OK;
}
