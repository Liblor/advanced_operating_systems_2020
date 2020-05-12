#include <aos/aos.h>
#include <maps/imx8x_map.h>
#include "block_driver.h"

static struct capref sdhc_cap;

static inline errval_t get_cap_io_dev_base(genpaddr_t *ret_base)
{
    struct capability capability;
    errval_t err;
    err = cap_direct_identify(cap_io_dev, &capability);
    if (err_is_fail(err)) {
        debug_printf("cap_direct_identify() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CAP_IDENTIFY);
    }
    *ret_base = get_address(&capability);
    return SYS_ERR_OK;
}

errval_t block_driver_init(lvaddr_t *ret_sdhc_vaddr)
{
    // TODO
    errval_t err;
    err = slot_alloc(&sdhc_cap);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc(..) failed: %s\n", err_getstring(err));
        return err;
    }
    genpaddr_t cap_io_dev_base;
    err = get_cap_io_dev_base(&cap_io_dev_base);
    if (err_is_fail(err)) {
        debug_printf("get_cap_io_dev_base(..) failed: %s\n", err_getstring(err));
        return err;
    }
    err = cap_retype(
            sdhc_cap,
            cap_io_dev,
            IMX8X_SDHC2_BASE - cap_io_dev_base,
            ObjType_DevFrame,
            ROUND_UP(IMX8X_SDHC_SIZE, BASE_PAGE_SIZE),
            1
    );
    if (err_is_fail(err)) {
        debug_printf("cap_retype(..) failed: %s\n", err_getstring(err));
        return err;
    }
    err = paging_map_frame_attr(
            get_current_paging_state(),
            (void **)&ret_sdhc_vaddr,
            IMX8X_SDHC_SIZE,
            sdhc_cap,
            VREGION_FLAGS_READ_WRITE_NOCACHE,
            0,
            0);
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame_attr(..) failed: %s\n", err_getstring(err));
        return err;
    }
    return SYS_ERR_OK;
}
