#include <aos/aos.h>
#include <aos/urpc.h>

static volatile struct urpc_shared_mem *urpc_shared_mem;

errval_t urpc_init(void)
{
    errval_t err;
    size_t urpc_frame_size;
    err = frame_alloc(&cap_urpc, URPC_SHARED_MEM_SIZE, &urpc_frame_size);
    if (err_is_fail(err)) {
        debug_printf("frame alloc for urpc failed: %s\n", err_getstring(err));
        return err;
    }
    return paging_map_frame(
            get_current_paging_state(),
            (void **) &urpc_shared_mem,
            URPC_SHARED_MEM_SIZE,
            cap_urpc,
            0,
            0
            );
}

errval_t urpc_send_boot_info(void)
{
    return SYS_ERR_OK;
}
