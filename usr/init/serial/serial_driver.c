#include <aos/aos.h>
#include <stdio.h>

#include "serial_driver.h"

#include <maps/imx8x_map.h>

#include <aos/inthandler.h>

struct serial_driver_state serial_state;

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


static void lpuart_iqr_handler(void *arg)
{
//    SERIAL_DEBUG("receiving iqr\n");

    errval_t err;
    char ret;
    err = lpuart_getchar(serial_state.lpuart3_state, &ret);
    if (err_is_fail(err)) {
        debug_printf("lpuart_getchar() failed: %s\n", err_getstring(err));
    }

#if 1
    // Debugging
    err = lpuart_putchar(serial_state.lpuart3_state, ret);
    if (err_is_fail(err)) {
        debug_printf("lpuart_putchar() failed: %s\n", err_getstring(err));
        abort();
    }
#endif
}

__inline
static errval_t setup_lpuart_irq(void)
{
    errval_t err;

    void *gic_base;
    err = map_device_into_vspace((IMX8X_GIC_DIST_BASE - IMX8X_START_DEV_RANGE),
                                 IMX8X_GIC_DIST_SIZE,
                                 &gic_base);

    if (err_is_fail(err)) {
        debug_printf("failed to map gic into vspace: %s\n", err_getstring(err));
        return err;
    }

    SERIAL_DEBUG("mapped gic at addr %p\n", gic_base);

    err = gic_dist_init(&serial_state.gic_dist_state, gic_base);

    if (err_is_fail(err)) {
        debug_printf("failed to call gic_dist_init:  %s\n", err_getstring(err));
        return err;
    }

    void *lpuart3_base;
    err = map_device_into_vspace((IMX8X_UART3_BASE - IMX8X_START_DEV_RANGE),
                                 IMX8X_UART_SIZE,
                                 &lpuart3_base);
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_PAGING_MAP_FRAME);
    }

    SERIAL_DEBUG("mapped lpuart3 at addr %p\n", gic_base);

    err = lpuart_init(&serial_state.lpuart3_state, lpuart3_base);

    if (err_is_fail(err)) {
        debug_printf("lpuart_init() failed: %s\n", err_getstring(err));
        return err_push(err, LPUART_ERR_INVALID_DEV);
    }

    SERIAL_DEBUG("initialized lpuart3\n");

#if 0
    while (1) {
        char ret;
        do {
            err = lpuart_getchar(serial_state.lpuart3_state, &ret);
        } while (err == LPUART_ERR_NO_DATA);
        if (err_is_fail(err)) {
            debug_printf("lpuart_getchar() failed: %s\n", err_getstring(err));
            abort();
        }
        SHELL_DEBUG("%c\n", ret);
    }
#endif

    err = inthandler_alloc_dest_irq_cap(IMX8X_UART3_INT,
                                        &serial_state.irq_dest_cap);
    if (err_is_fail(err)) {
        debug_printf("failed alloc dest irq cap (inthandler_alloc_dest_irq_cap):  %s\n",
                     err_getstring(err));
        return err;
    }

    err = inthandler_setup(serial_state.irq_dest_cap, get_default_waitset(),
                           MKCLOSURE(lpuart_iqr_handler, NULL));
    if (err_is_fail(err)) {
        debug_printf("failed to call inthandler_setup:  %s\n", err_getstring(err));
        return err;
    }

    err = gic_dist_enable_interrupt(serial_state.gic_dist_state, IMX8X_UART3_INT, 1, 0);
    if (err_is_fail(err)) {
        debug_printf("failed to call gic_dist_enable_interrupt:  %s\n", err_getstring(err));
        return err;
    }

    err = lpuart_enable_interrupt(serial_state.lpuart3_state);
    if (err_is_fail(err)) {
        debug_printf("failed to call lpuart_enable_interrupt:  %s\n", err_getstring(err));
        return err;
    }

    SERIAL_DEBUG("lpuart3 fully initialized and iqr handler registered\n");
    return SYS_ERR_OK;
}

errval_t serial_driver_read(char *ret_c)
{
    assert(serial_state.lpuart3_state != NULL);
    return SYS_ERR_NOT_IMPLEMENTED;
}

errval_t serial_driver_write(char c)
{
    assert(serial_state.lpuart3_state != NULL);
    return lpuart_putchar(serial_state.lpuart3_state, c);
}

errval_t serial_driver_init(void)
{
    errval_t err;
    memset(&serial_state, 0, sizeof(struct serial_driver_state));

    err = setup_lpuart_irq();
    if (err_is_fail(err)) {
        debug_printf("failed to setup lpuart for interruptst:  %s\n", err_getstring(err));
        return err;
    }

    return SYS_ERR_OK;
}