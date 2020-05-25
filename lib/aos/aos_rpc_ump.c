#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>
#include <aos/debug.h>
#include <aos/kernel_cap_invocations.h>

#define BARRIER_DATA __asm volatile("dmb sy\n");

/*
 * This needs to be called by the establisher first, to make sure all the lines
 * are set to zero prior to use.
 */
errval_t aos_rpc_ump_init(
    struct aos_rpc *rpc,
    struct capref frame_cap,
    bool is_establisher
)
{
    errval_t err;

    assert(rpc != NULL);

    err = aos_rpc_init(rpc, RpcTypeUmp);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_init() failed: %s\n", err_getstring(err));
        return err;
    }

    char *vaddr = NULL;

    err = paging_map_frame(
        get_current_paging_state(),
        (void **) &vaddr,
        UMP_SHARED_FRAME_SIZE,
        frame_cap,
        NULL,
        NULL
    );
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }

    assert(vaddr != NULL);

    rpc->ump.tx_slot_next = 0;
    rpc->ump.rx_slot_next = 0;

    if (is_establisher) {
        memset(vaddr, 0x00, UMP_SHARED_FRAME_SIZE);
        rpc->ump.tx = (struct ump_shared_half *) vaddr;
        rpc->ump.rx = (struct ump_shared_half *) (vaddr + sizeof(struct ump_shared_half));
    } else {
        rpc->ump.rx = (struct ump_shared_half *) vaddr;
        rpc->ump.tx = (struct ump_shared_half *) (vaddr + sizeof(struct ump_shared_half));
    }

    rpc->ump.frame_cap = frame_cap;

    return SYS_ERR_OK;
}

static bool aos_rpc_ump_can_receive(
    struct aos_rpc *rpc
)
{
    assert(rpc != NULL);
    assert(rpc->type == RpcTypeUmp);

    thread_mutex_lock_nested(&rpc->mutex);

    struct ump_message *ump_message = &rpc->ump.rx->lines[rpc->ump.rx_slot_next];
    bool can_receive = ump_message->used;

    thread_mutex_unlock(&rpc->mutex);

    return can_receive;
}

static errval_t aos_rpc_ump_forge_capability(
    const genpaddr_t base,
    const gensize_t size,
    struct capref *cap
)
{
    errval_t err;

    assert(cap != NULL);

    if (capref_is_null(*cap)) {
        err = slot_alloc(cap);
        if (err_is_fail(err)) {
            debug_printf("slot_alloc() failed: %s\n", err_getstring(err));
            return err_push(err, LIB_ERR_SLOT_ALLOC);
        }
    }

    err = frame_forge(
        *cap,
        base,
        ROUND_UP(size, BASE_PAGE_SIZE),
        disp_get_core_id()
    );
    if (err_is_fail(err)) {
        debug_printf("frame_forge() failed: %s\n", err_getstring(err));
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_ump_receive(
    struct aos_rpc *rpc,
    struct rpc_message **message
)
{
    errval_t err;

    assert(rpc != NULL);
    assert(rpc->type == RpcTypeUmp);
    assert(message != NULL);
    assert(rpc->ump.rx != NULL);

    thread_mutex_lock_nested(&rpc->mutex);

    bool is_initialized = false;

    uint64_t total_length = 0;
    uint64_t bytes_received = 0;

    do {
        struct ump_message *ump_message = &rpc->ump.rx->lines[rpc->ump.rx_slot_next];

        // Block until we can receive a message.
        while (!ump_message->used) {
            // TODO: Investigate why this breaks sdhc
            thread_yield();
        }
        BARRIER_DATA;

        struct rpc_message_part *msg_part = (struct rpc_message_part *) ump_message->data;

        size_t max_copy = UMP_MESSAGE_DATA_SIZE;
        char *read_from = (char *) msg_part;

        if (!is_initialized) {
            total_length = msg_part->payload_length;
            bytes_received = 0;

            max_copy -= sizeof(struct rpc_message_part);
            read_from += sizeof(struct rpc_message_part);

            if (*message == NULL) {
                *message = calloc(1, sizeof(struct rpc_message) + total_length);
            }
            if (*message == NULL) {
                err = LIB_ERR_MALLOC_FAIL;
                goto cleanup;
            }

            (*message)->msg.method = msg_part->method;
            (*message)->msg.status = msg_part->status;
            (*message)->msg.payload_length = msg_part->payload_length;

            const genpaddr_t base = ump_message->cap_base;
            const gensize_t size = ump_message->cap_size;

            if (size > 0) {
                aos_rpc_ump_forge_capability(base, size, &(*message)->cap);
            }

            is_initialized = true;
        }

        const uint64_t to_copy = MIN(max_copy, total_length - bytes_received);
        memcpy(((char *) (*message)->msg.payload) + bytes_received, read_from, to_copy);
        bytes_received += to_copy;

        rpc->ump.rx_slot_next++;
        rpc->ump.rx_slot_next %= UMP_RING_BUFFER_LINES;

        BARRIER_DATA;
        ump_message->used = 0;
    } while (bytes_received < total_length);

    err = SYS_ERR_OK;

cleanup:
    thread_mutex_unlock(&rpc->mutex);

    return err;
}

errval_t aos_rpc_ump_receive_non_block(
    struct aos_rpc *rpc,
    struct rpc_message **message
)
{
    errval_t err;

    assert(rpc != NULL);
    assert(rpc->type == RpcTypeUmp);
    assert(message != NULL);
    assert(rpc->ump.rx != NULL);

    thread_mutex_lock_nested(&rpc->mutex);

    bool can_receive = aos_rpc_ump_can_receive(rpc);

    if (!can_receive) {
        err = SYS_ERR_OK;
        goto cleanup;
    }

    err = aos_rpc_ump_receive(rpc, message);
    if (err_is_fail(err)) {
        goto cleanup;
    }

    err = SYS_ERR_OK;

cleanup:
    thread_mutex_unlock(&rpc->mutex);

    return err;
}

errval_t aos_rpc_ump_send_and_wait_recv(
    struct aos_rpc *rpc,
    struct rpc_message *send,
    struct rpc_message **recv
)
{
    errval_t err;

    assert(rpc != NULL);
    assert(rpc->type == RpcTypeUmp);
    assert(send != NULL);
    assert(recv != NULL);

    // TODO Do we need to lock the mutex here?

    // Send message
    err = aos_rpc_ump_send_message(rpc, send);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_send_message() failed: %s\n", err_getstring(err));
        return err;
    }

    // Wait for response and read response
    err = aos_rpc_ump_receive(rpc, recv);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_receive() failed: %s\n", err_getstring(err));
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_ump_send_message(
    struct aos_rpc *rpc,
    struct rpc_message *msg
)
{
    errval_t err;

    assert(rpc != NULL);
    assert(rpc->type == RpcTypeUmp);
    assert(msg != NULL);

    uint64_t cap_base = 0;
    uint64_t cap_size = 0;

    if (!capref_is_null(msg->cap)) {
        struct frame_identity fi;

        err = frame_identify(msg->cap, &fi);
        if (!err_is_ok(err)) { // XXX: use !err_is_ok to work well with debug macro
            struct capability any_cap_id;
            err = cap_direct_identify(msg->cap, &any_cap_id);
            if (err_is_fail(err)) {
                debug_printf("frame_identify() or cap_direct_identify() failed: %s\n", err_getstring(err));
                return err;

            } else {
                cap_base = get_address(&any_cap_id);
                cap_size = get_size(&any_cap_id);
            }
        } else {
            cap_base = fi.base;
            cap_size = fi.bytes;
        }
    }

    const uint8_t *msg_base = (uint8_t *) &msg->msg;
    const uint64_t msg_size = sizeof(struct rpc_message_part) + msg->msg.payload_length;
    bool first = true;
    uint64_t size_sent = 0;

    thread_mutex_lock_nested(&rpc->mutex);

    while (size_sent < msg_size) {
        uint64_t to_send = MIN(UMP_MESSAGE_DATA_SIZE, msg_size - size_sent);
        uint64_t tx_slot = rpc->ump.tx_slot_next;
        struct ump_message *slot = &rpc->ump.tx->lines[tx_slot];

        // Wait until the next tx slot is free
        while(slot->used == 1) {
            thread_yield();
        }
        BARRIER_DATA;

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
        rpc->ump.tx_slot_next %= UMP_RING_BUFFER_LINES;

        BARRIER_DATA;
        slot->used = 1;
    }

    thread_mutex_unlock(&rpc->mutex);

    return SYS_ERR_OK;
}
