#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>
#include <rpc/server/ump.h>
#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>

#include "block_driver.h"

static struct rpc_ump_server server;
struct sdhc_s *sdhc_s;


__unused static errval_t reply_block(
    struct aos_rpc *rpc,
    char *buf
) {
    errval_t err;

    struct rpc_message *msg = malloc(sizeof(struct rpc_message) + SDHC_BLOCK_SIZE);

    msg->cap = NULL_CAP;
    msg->msg.method = Method_Block_Driver_Read_Block;
    // TODO
    msg->msg.payload_length = SDHC_BLOCK_SIZE;
    msg->msg.status = Status_Ok;
    //msg.msg.payload[0] = c;

    err = aos_rpc_ump_send_message(rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "ump_send_message failed\n");
        free(msg);
        return err;
    }

    free(msg);
    return SYS_ERR_OK;
}

static void service_recv_cb(struct rpc_message *msg, void *callback_state, struct aos_rpc *rpc, void *server_state)
{
    switch (msg->msg.method) {
        case Method_Block_Driver_Read_Block:
            // TODO
            break;
        case Method_Block_Driver_Write_Block:
            // TODO
            break;
        default:
            break;
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
    err = paging_map_frame(
        get_current_paging_state(),
        (void **)&st->read_vaddr,
        size, st->frame,
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
