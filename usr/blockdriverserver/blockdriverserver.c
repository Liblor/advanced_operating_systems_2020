#include <aos/aos.h>
#include <aos/cache.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>
#include <rpc/server/ump.h>
#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>
#include <aos/nameserver.h>

struct block_driver_state {
    struct capref sdhc;     ///< ObjType_DevFrame capability to SDHC
    struct capref frame;    ///< Mapped frame used for read/write_vaddr
    lvaddr_t sdhc_vaddr;    ///< Virtual address of mapped SDHC (is passed to sdhc_init)
    lvaddr_t write_vaddr;   ///< Virtual address of memory region that is used to write block to SDHC
    lvaddr_t read_vaddr;    ///< Virtual address of memory region that is used to read block from SDHC
    lpaddr_t write_paddr;   ///< write_vaddr maps to this physical address
    lpaddr_t read_paddr;    ///< read_vaddr maps to this physical address
};

static struct sdhc_s *sdhc_s;

static inline errval_t fail_msg(
    enum rpc_message_method method,
    struct rpc_message **ret_msg
) {
    *ret_msg = malloc(sizeof(struct rpc_message));
    if (*ret_msg == NULL) { return LIB_ERR_MALLOC_FAIL; }
    (*ret_msg)->cap = NULL_CAP;
    (*ret_msg)->msg.method = method;
    (*ret_msg)->msg.payload_length = 0;
    (*ret_msg)->msg.status = Status_Error;
    return SYS_ERR_OK;
}

static inline errval_t success_msg(
    enum rpc_message_method method,
    struct rpc_message **ret_msg
) {
    *ret_msg = malloc(sizeof(struct rpc_message));
    if (*ret_msg == NULL) { return LIB_ERR_MALLOC_FAIL; }
    (*ret_msg)->cap = NULL_CAP;
    (*ret_msg)->msg.method = method;
    (*ret_msg)->msg.payload_length = 0;
    (*ret_msg)->msg.status = Status_Ok;
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
    struct block_driver_state *server_state,
    struct rpc_message *msg,
    struct rpc_message **ret_msg
) {
    assert(msg->msg.method == Method_Block_Driver_Read_Block);
    errval_t err;
    uint32_t index;
    memcpy(&index, msg->msg.payload, sizeof(uint32_t));
    err = read_block(index, server_state);
    if (err_is_fail(err)) {
        fail_msg(Method_Block_Driver_Read_Block, ret_msg);
        return err;
    }
    *ret_msg = malloc(sizeof(struct rpc_message) + SDHC_BLOCK_SIZE);
    if (*ret_msg == NULL) {
        // fail_msg may be allocatable as it is smaller
        return fail_msg(Method_Block_Driver_Read_Block, ret_msg);
    }

    (*ret_msg)->cap = NULL_CAP;
    (*ret_msg)->msg.method = Method_Block_Driver_Read_Block;
    (*ret_msg)->msg.payload_length = SDHC_BLOCK_SIZE;
    (*ret_msg)->msg.status = Status_Ok;
    memcpy((*ret_msg)->msg.payload, (char *)server_state->read_vaddr, SDHC_BLOCK_SIZE);
    return SYS_ERR_OK;
}

static errval_t handle_write_block(
    struct block_driver_state *server_state,
    struct rpc_message *msg,
    struct rpc_message **ret_msg
) {
    assert(msg->msg.method == Method_Block_Driver_Write_Block);
    assert(msg->msg.payload_length == sizeof(uint32_t) + SDHC_BLOCK_SIZE);
    errval_t err;
    uint32_t index;
    memcpy(&index, msg->msg.payload, sizeof(index));
    memcpy((void *)server_state->write_vaddr, msg->msg.payload + sizeof(index), SDHC_BLOCK_SIZE);
    err = write_block(index, server_state);
    if (err_is_fail(err)) {
        fail_msg(Method_Block_Driver_Write_Block, ret_msg);
        return err;
    }
    success_msg(Method_Block_Driver_Write_Block, ret_msg);
    return SYS_ERR_OK;
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

static void ns_service_handler(
    void *st,
    void *message,
    size_t bytes,
    void **response,
    size_t *response_bytes,
    struct capref tx_cap,
    struct capref *rx_cap)
{
    errval_t err;
    struct rpc_message *msg = message;
    struct rpc_message *resp_msg = NULL;
    switch (msg->msg.method) {
        case Method_Block_Driver_Read_Block:
            err = handle_read_block(st, msg, &resp_msg);
            break;
        case Method_Block_Driver_Write_Block:
            err = handle_write_block(st, msg, &resp_msg);
            break;
        default:
            debug_printf("unknown method given: %d\n", msg->msg.method);
            err = AOS_ERR_LMP_MSGTYPE_UNKNOWN;      // TODO: fix error code
            break;
    }
    if (err_is_fail(err)) {
        debug_printf("ns_service_handler(..) in blockdriverserver.c failed: %s\n", err_getstring(err));
    }
    if (resp_msg == NULL) {
        *response = NULL;
        *response_bytes = 0;
    } else {
        *response = resp_msg;
        *response_bytes = sizeof(struct rpc_message) + resp_msg->msg.payload_length;
    }
}

int main(int argc, char *argv[])
{
    errval_t err;
    debug_printf("Blockdriverserver spawned.\n");
    struct block_driver_state *st = malloc(sizeof(struct block_driver_state));
    if (st == NULL) {
        return 1;
    }
    err = init_block_driver_state(st);
    if (err_is_fail(err)) {
        return 1;
    }
    err = nameservice_register(NAMESERVICE_BLOCKDRIVER, ns_service_handler, st);
    if (err_is_fail(err)) {
        debug_printf("nameservice_register() failed: %s\n", err_getstring(err));
        abort();
    }
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
        thread_yield();
    }
    return SYS_ERR_OK;
}
