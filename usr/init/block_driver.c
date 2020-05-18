#include <aos/aos.h>
#include <aos/cache.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>
#include <rpc/server/ump.h>
#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>

#include "block_driver.h"

static struct rpc_ump_server server;
static struct sdhc_s *sdhc_s;

static inline errval_t reply_error(
        struct aos_rpc *rpc,
        enum rpc_message_method method
) {
    struct rpc_message fail_msg;
    fail_msg.cap = NULL_CAP;
    fail_msg.msg.method = method;
    fail_msg.msg.payload_length = 0;
    fail_msg.msg.status = Status_Error;
    return aos_rpc_ump_send_message(rpc, &fail_msg);
}

static inline errval_t reply_success(
        struct aos_rpc *rpc,
        enum rpc_message_method method
) {
    struct rpc_message msg;
    msg.cap = NULL_CAP;
    msg.msg.method = method;
    msg.msg.payload_length = 0;
    msg.msg.status = Status_Ok;
    return aos_rpc_ump_send_message(rpc, &msg);
}

static errval_t reply_block(
    struct aos_rpc *rpc,
    char *buf
) {
    errval_t err;

    struct rpc_message *msg = malloc(sizeof(struct rpc_message) + SDHC_BLOCK_SIZE);
    if (msg == NULL) {
        // optimistic send, don't handle error
        reply_error(rpc, Method_Block_Driver_Read_Block);
        return LIB_ERR_MALLOC_FAIL;
    }

    msg->cap = NULL_CAP;
    msg->msg.method = Method_Block_Driver_Read_Block;
    msg->msg.payload_length = SDHC_BLOCK_SIZE;
    msg->msg.status = Status_Ok;
    memcpy(msg->msg.payload, buf, SDHC_BLOCK_SIZE);

    err = aos_rpc_ump_send_message(rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "ump_send_message failed\n");
        free(msg);
        return err;
    }

    free(msg);
    return SYS_ERR_OK;
}

static inline errval_t read_block(
    uint32_t index,
    struct block_driver_state *server_state
) {
    errval_t err;
    arm64_dcache_wbinv_range(server_state->read_vaddr, SDHC_BLOCK_SIZE);
    err = sdhc_read_block(sdhc_s, index, server_state->read_paddr);
    if (err_is_fail(err)) { return err; }
    return SYS_ERR_OK;
}

static inline errval_t write_block(
        uint32_t index,
        struct block_driver_state *server_state
) {
    errval_t err;
    arm64_dcache_wb_range(server_state->write_vaddr, SDHC_BLOCK_SIZE);
    err = sdhc_write_block(sdhc_s, index, server_state->write_paddr);
    if (err_is_fail(err)) { return err; }
    return SYS_ERR_OK;
}

static errval_t handle_read_block(
    struct aos_rpc *rpc,
    struct rpc_message *msg,
    struct block_driver_state *server_state
) {
    assert(msg->msg.method == Method_Block_Driver_Read_Block);
    errval_t err;
    uint32_t index;
    memcpy(&index, msg->msg.payload, sizeof(uint32_t));
    err = read_block(index, server_state);
    if (err_is_fail(err)) {
        reply_error(rpc, Method_Block_Driver_Read_Block);
        return err;
    }
    err = reply_block(rpc, (char *)server_state->read_vaddr);
    if (err_is_fail(err)) {
        reply_error(rpc, Method_Block_Driver_Read_Block);
        return err;
    }
    return SYS_ERR_OK;
}

static errval_t handle_write_block(
    struct aos_rpc *rpc,
    struct rpc_message *msg,
    struct block_driver_state *server_state
) {
    assert(msg->msg.method == Method_Block_Driver_Write_Block);
    assert(msg->msg.payload_length == sizeof(uint32_t) + SDHC_BLOCK_SIZE);
    errval_t err;
    uint32_t index;
    memcpy(&index, msg->msg.payload, sizeof(index));
    memcpy((void *)server_state->write_vaddr, msg->msg.payload + sizeof(index), SDHC_BLOCK_SIZE);
    err = write_block(index, server_state);
    if (err_is_fail(err)) {
        reply_error(rpc, Method_Block_Driver_Write_Block);
        return err;
    }
    return reply_success(rpc, Method_Block_Driver_Write_Block);
}

static void service_recv_cb(
    struct rpc_message *msg,
    void *callback_state,
    struct aos_rpc *rpc,
    void *server_state
) {
    errval_t err = SYS_ERR_OK;
    switch (msg->msg.method) {
        case Method_Block_Driver_Read_Block:
            err = handle_read_block(rpc, msg, server_state);
            break;
        case Method_Block_Driver_Write_Block:
            err = handle_write_block(rpc, msg, server_state);
            break;
        default:
            debug_printf("Unhandled message send to block driver\n");
            break;
    }
    if (err_is_fail(err)) {
        debug_printf("service_recv_cb(..) in block_driver.c failed: %s\n", err_getstring(err));
    }
}

errval_t block_driver_add_client(struct aos_rpc *rpc, coreid_t mpid)
{
    return rpc_ump_server_add_client(&server, rpc);
}

errval_t block_driver_serve_next(void)
{
    return rpc_ump_server_serve_next(&server);
}

static inline errval_t init_block_driver_state(struct block_driver_state *st)
{
    errval_t err;
    err = map_driver(IMX8X_SDHC2_BASE, IMX8X_SDHC_SIZE, false, &st->sdhc, &st->sdhc_vaddr);
    if(err_is_fail(err)) {
        debug_printf("block_driver_init() failed: %s\n", err_getstring(err));
        abort();
    }
    err = sdhc_init(&sdhc_s, (void *)st->sdhc_vaddr);
    if (err_is_fail(err)) {
        return err;
    }
    size_t size;
    err = frame_alloc(&st->frame, BASE_PAGE_SIZE, &size);
    if (err_is_fail(err)) {
        return err;
    }
    if (size < BASE_PAGE_SIZE) {
        return LIB_ERR_FRAME_ALLOC_SIZE;
    }
    err = paging_map_frame_attr(
        get_current_paging_state(),
        (void **)&st->read_vaddr,
        size, st->frame,
        VREGION_FLAGS_READ_WRITE,
        0,
        0
    );
    if (err_is_fail(err)) {
        return err;
    }
    struct frame_identity frame_identity;
    err = frame_identify(st->frame, &frame_identity);
    if (err_is_fail(err)) {
        return err;
    }
    st->read_paddr = frame_identity.base;
    st->write_vaddr = st->read_vaddr + SDHC_BLOCK_SIZE;
    st->write_paddr = st->read_paddr + SDHC_BLOCK_SIZE;
    return SYS_ERR_OK;
}

errval_t block_driver_init(void)
{
    errval_t err;
    struct block_driver_state *st = malloc(sizeof(struct block_driver_state));
    if (st == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    err = init_block_driver_state(st);
    if (err_is_fail(err)) {
        return err;
    }
    err = rpc_ump_server_init(
        &server,
        service_recv_cb,
        NULL,
        NULL,
        st
    );
    if (err_is_fail(err)) {
        debug_printf("rpc_ump_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
