#include <aos/aos.h>
#include <stdio.h>
#include <maps/imx8x_map.h>
#include <aos/inthandler.h>
#include "serial_facade.h"

static errval_t map_device_into_vspace(
        gensize_t offset,
        size_t objsize,
        void **ret_vaddr)
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

__unused
static void lpuart_iqr_handler(void *arg)
{
    // SERIAL_FACADE_DEBUG("serial_driver iqr\n");

    assert(arg != NULL);
    struct serial_facade *state = (struct serial_facade *) arg;

    errval_t err;
    char ret;
    err = lpuart_getchar(state->lpuart3_state, &ret);
    if (err_is_fail(err)) {
        debug_printf("lpuart_getchar() failed: %s\n", err_getstring(err));
    } else {
        if (state->read_cb != NULL) {
            state->read_cb(ret, state->read_cb_args);
        }
    }
}

__inline
static errval_t setup_lpuart_irq(
        struct serial_facade *serial_state)
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
    SERIAL_FACADE_DEBUG("mapped gic at addr %p\n", gic_base);

    err = gic_dist_init(&serial_state->gic_dist_state, gic_base);

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
    SERIAL_FACADE_DEBUG("mapped lpuart3 at addr %p\n", gic_base);

    err = lpuart_init(&serial_state->lpuart3_state, lpuart3_base);

    if (err_is_fail(err)) {
        debug_printf("lpuart_init() failed: %s\n", err_getstring(err));
        return err_push(err, LPUART_ERR_INVALID_DEV);
    }
    SERIAL_FACADE_DEBUG("initialized lpuart3\n");

#ifndef SERIAL_FACADE_DISABLE_IQR

    err = inthandler_alloc_dest_irq_cap(IMX8X_UART3_INT,
                                        &serial_state->irq_dest_cap);
    if (err_is_fail(err)) {
        debug_printf("failed alloc dest irq cap (inthandler_alloc_dest_irq_cap):  %s\n",
                     err_getstring(err));
        return err;
    }

    err = inthandler_setup(serial_state->irq_dest_cap,
                           get_default_waitset(),
                           MKCLOSURE(lpuart_iqr_handler, serial_state));
    if (err_is_fail(err)) {
        debug_printf("failed to call inthandler_setup:  %s\n", err_getstring(err));
        return err;
    }

    err = gic_dist_enable_interrupt(serial_state->gic_dist_state,
                                    IMX8X_UART3_INT,
                                    serial_state->target_cpu,
                                    0);
    if (err_is_fail(err)) {
        debug_printf("failed to call gic_dist_enable_interrupt:  %s\n", err_getstring(err));
        return err;
    }

    err = lpuart_enable_interrupt(serial_state->lpuart3_state);
    if (err_is_fail(err)) {
        debug_printf("failed to call lpuart_enable_interrupt:  %s\n", err_getstring(err));
        return err;
    }

    SERIAL_FACADE_DEBUG("lpuart3 fully initialized and iqr handler registered\n");

#endif

    return SYS_ERR_OK;
}

errval_t serial_facade_set_read_cb(
        struct serial_facade *state,
        serial_facade_read_cb cb,
        void *args)
{
    assert(state != NULL);
    state->read_cb = cb;
    state->read_cb_args = args;
    return SYS_ERR_OK;
}

errval_t serial_facade_write(
        struct serial_facade *state,
        char c)
{
    assert(state != NULL);
    assert(state->lpuart3_state != NULL);
    return lpuart_putchar(state->lpuart3_state, c);
}

errval_t serial_facade_write_str(
        struct serial_facade *state,
        const char *str,
        size_t len)
{
    errval_t err = SYS_ERR_OK;
    for (int i = 0; i < len && err_is_ok(err); i++) {
        err = serial_facade_write(state, *(str + i));
    }
    return err;
}

errval_t serial_facade_init(
        struct serial_facade *state,
        uint8_t target_cpu)
{
    errval_t err;
    memset(state, 0, sizeof(struct serial_facade));
    state->target_cpu = target_cpu;

    err = setup_lpuart_irq(state);
    if (err_is_fail(err)) {
        debug_printf("failed to setup lpuart for iqrs:  %s\n", err_getstring(err));
        return err;
    }

    return SYS_ERR_OK;
}