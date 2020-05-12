
// Created by b on 5/9/20.
//

#include <aos/aos.h>
#include <stdio.h>

#include "shell.h"
#include <drivers/lpuart.h>
#include <maps/imx8x_map.h>

static errval_t map_device_into_vspace(gensize_t offset, size_t objsize, void **ret_vaddr)
{
    errval_t err;
    objsize = ROUND_UP(objsize, BASE_PAGE_SIZE);

    struct capref dev_cap;
    err = slot_alloc(&dev_cap);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    err = cap_retype(
            dev_cap,
            cap_io_dev,
            offset,
            ObjType_DevFrame,
            objsize,
            1);

    if (err_is_fail(err)) {
        debug_printf("cap_retype() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    err = paging_map_frame_attr(get_current_paging_state(),
                                ret_vaddr,
                                objsize,
                                dev_cap,
                                VREGION_FLAGS_READ_WRITE_NOCACHE,
                                0,
                                0);

    if (err_is_fail(err)) {
        debug_printf("paging_map_frame_attr() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }

    return SYS_ERR_OK;
}

errval_t shell_init(void)
{
    errval_t err;

    void * lpuart3_base;
    err = map_device_into_vspace((IMX8X_UART3_BASE - IMX8X_START_DEV_RANGE), IMX8X_UART_SIZE,
                                 &lpuart3_base);
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }

    SHELL_DEBUG("ok so far, lpuart3 data at %p\n", lpuart3_base);

    struct lpuart_s *lpuart;
    err = lpuart_init(&lpuart, lpuart3_base);

    if (err_is_fail(err)) {
        debug_printf("lpuart_init() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }

    SHELL_DEBUG("lpuart_init ok %p\n");

    return SYS_ERR_OK;
}