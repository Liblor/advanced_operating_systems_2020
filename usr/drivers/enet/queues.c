#include "queues.h"

#include <devif/queue_interface_backend.h>
#include <devif/backends/net/enet_devif.h>
#include <aos/aos.h>
#include <aos/debug.h>
#include <aos/deferred.h>
#include <driverkit/driverkit.h>
#include <dev/imx8x/enet_dev.h>

static errval_t queues_initialize_rx(
    struct enet_driver_state *st,
    regionid_t *rid
)
{
    errval_t err;

    assert(st != NULL);

    /* Create receive queue. */
    err = enet_rx_queue_create(&st->rxq, st->d);
    if (err_is_fail(err)) {
        debug_printf("enet_rx_queue_create() failed: %s\n", err_getstring(err));
        return err_push(err, DEVQ_ERR_INIT_QUEUE);
    }

    const gensize_t rx_size = RX_RING_SIZE * ENET_MAX_BUF_SIZE;

    /* Get some memory for receive buffers. */
    err = frame_alloc(&st->rx_mem, rx_size, NULL);
    if (err_is_fail(err)) {
        debug_printf("frame_alloc() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    /* Map the receive buffers into virtual memory. */
    err = paging_map_frame(
        get_current_paging_state(),
        (void **) &st->rx_base,
        rx_size,
        st->rx_mem,
        NULL,
        NULL
    );
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame_attr() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_VSPACE_MAP);
    }

    /* Register receive queue. */
    err = devq_register((struct devq *)st->rxq, st->rx_mem, rid);
    if (err_is_fail(err)) {
        debug_printf("enet_rx_queue_create() failed: %s\n", err_getstring(err));
        return err_push(err, DEVQ_ERR_REGISTER_REGION);
    }

    /* Enqueue receive buffers. */
    for (int i = 0; i < st->rxq->size - 1; i++) {
        err = devq_enqueue((struct devq *)st->rxq, *rid, i * (ENET_MAX_BUF_SIZE), ENET_MAX_BUF_SIZE, 0, ENET_MAX_BUF_SIZE, 0);
        if (err_is_fail(err)) {
            return err;
        }
    }

    return SYS_ERR_OK;
}

static errval_t queues_initialize_tx(
    struct enet_driver_state *st,
    regionid_t *rid
)
{
    errval_t err;

    assert(st != NULL);

    /* Create send queue. */
    err = enet_tx_queue_create(&st->txq, st->d);
    if (err_is_fail(err)) {
        debug_printf("enet_rx_queue_create() failed: %s\n", err_getstring(err));
        return err_push(err, DEVQ_ERR_INIT_QUEUE);
    }

    const gensize_t tx_size = TX_RING_SIZE * ENET_MAX_BUF_SIZE;

    /* Get some memory for send buffers. */
    err = frame_alloc(&st->tx_mem, tx_size, NULL);
    if (err_is_fail(err)) {
        debug_printf("frame_alloc() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    /* Map the send buffers into virtual memory. */
    err = paging_map_frame(
        get_current_paging_state(),
        (void **) &st->tx_base,
        tx_size,
        st->tx_mem,
        NULL,
        NULL
    );
    if (err_is_fail(err)) {
        debug_printf("paging_map_frame() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_VSPACE_MAP);
    }

    /* Register send queue. */
    err = devq_register((struct devq *)st->txq, st->tx_mem, rid);
    if (err_is_fail(err)) {
        debug_printf("enet_rx_queue_create() failed: %s\n", err_getstring(err));
        return err_push(err, DEVQ_ERR_REGISTER_REGION);
    }

    return SYS_ERR_OK;
}

errval_t queues_initialize(
    struct enet_driver_state *st,
    regionid_t *rx_rid,
    regionid_t *tx_rid
)
{
    errval_t err;

    assert(st != NULL);

    debug_printf("Initializing RX queue...\n");
    err = queues_initialize_rx(st, rx_rid);
    if (err_is_fail(err)) {
        debug_printf("RX Queue initialization failed.\n");
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    debug_printf("Initializing TX queue...\n");
    err = queues_initialize_tx(st, tx_rid);
    if (err_is_fail(err)) {
        debug_printf("TX Queue initialization failed.\n");
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    return SYS_ERR_OK;
}
