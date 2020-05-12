//
// Created by b on 5/9/20.
//

#include <aos/aos.h>
#include <stdio.h>

#include "shell.h"
#include <drivers/lpuart.h>
#include <maps/imx8x_map.h>

errval_t shell_init(void)
{
    errval_t err;

    struct capability io_dev_info;
    err = cap_direct_identify(cap_io_dev, &io_dev_info);
    if (err_is_fail(err)) {
        debug_printf("cap_direct_identify() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_CAP_IDENTIFY);
    }

    struct capref dev_frame;
    err = slot_alloc(&dev_frame);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    gensize_t io_dev_size = get_size(&io_dev_info);

    err = cap_retype(dev_frame,
                     cap_io_dev,
                     0,
                     ObjType_DevFrame,
                     io_dev_size,
                     1);
    if (err_is_fail(err)) {
        debug_printf("cap_retype() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    char *io_dev_addr;
    err = paging_map_frame(get_current_paging_state(),
                           (void **) &io_dev_addr,
                           io_dev_size,
                           dev_frame,
                           0,
                           0);
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }

    debug_printf("ok so far\n");

    return SYS_ERR_OK;
}