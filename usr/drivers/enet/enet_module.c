#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <aos/aos.h>
#include <devif/queue_interface_backend.h>
#include <aos/networking.h>
#include <aos/debug.h>
#include <aos/deferred.h>
#include <dev/imx8x/enet_dev.h>
#include <aos/nameserver.h>

#include <maps/imx8x_map.h> // IMX8X_ENET_BASE, IMX8X_ENET_SIZE

#include "enet.h"
#include "device.h"
#include "queues.h"
#include "ethernet.h"
#include "udp.h"
#include "router.h"

static errval_t enet_initialize_device(
    struct enet_driver_state *state
)
{
    errval_t err;

    assert(state != NULL);

    struct capref cap;
    const genpaddr_t base = IMX8X_ENET_BASE;
    const gensize_t size = IMX8X_ENET_SIZE;

    err = map_driver(
        base,
        size,
        false,
        &cap,
        (lvaddr_t *) &state->d_vaddr
    );
    if (err_is_fail(err)) {
        debug_printf("Failed mapping device memory.\n");
        return err;
    }

    if (state->d_vaddr == (lvaddr_t) NULL) {
        USER_PANIC("ENET: No register region mapped\n");
    }

    /* Initialize Mackerel binding */
    state->d = (enet_t *) malloc(sizeof(enet_t));
    enet_initialize(state->d, (void *) state->d_vaddr);

    assert(state->d != NULL);
    enet_read_mac(state);

    err = enet_probe(state);
    if (err_is_fail(err)) {
        /* TODO: Cleanup. */
        return err;
    }

    err = enet_init(state);
    if (err_is_fail(err)) {
        /* TODO: Cleanup. */
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t enet_serve(
    struct enet_driver_state *state
)
{
    errval_t err;

    assert(state != NULL);

    struct devq_buf buf;

    err = devq_dequeue(
        (struct devq *) state->rxq,
        &buf.rid,
        &buf.offset,
        &buf.length,
        &buf.valid_data,
        &buf.valid_length,
        &buf.flags
    );

    if (err_is_fail(err) && err_no(err) == DEVQ_ERR_QUEUE_EMPTY) {
        return SYS_ERR_OK;
    } else if (err_is_fail(err)) {
        debug_printf("devq_dequeue() failed: %s\n", err_getstring(err));
        return err;
    }

    const lvaddr_t base = state->rx_base + buf.offset + buf.valid_data;

    ENET_DEBUG("Received packet of size %lu.\n", buf.valid_length);

    err = ethernet_process(&state->eth_state, base, buf.valid_length);
    if (err_is_fail(err)) {
        debug_printf("ethernet_process() failed: %s\n", err_getstring(err));
        /* We do not need to return, this error is not critical. */
    }

    /* Hand the buffer back so the device can use it again. */
    err = devq_enqueue(
        (struct devq *) state->rxq,
        buf.rid,
        buf.offset,
        buf.length,
        buf.valid_data,
        buf.valid_length,
        buf.flags
    );
    if (err_is_fail(err)) {
        return SYS_ERR_NOT_IMPLEMENTED;
    }

    return SYS_ERR_OK;
}

static void serve_periodic_events(
    void *args
)
{
    errval_t err;

    struct enet_driver_state *state = args;

    err = enet_serve(state);
    if (err_is_fail(err)) {
        debug_printf("Failuring during serve routine.\n");
    }
}

static errval_t setup_periodic_events(
    struct periodic_event *periodic_ev,
    struct enet_driver_state *state
)
{
    errval_t err;

    memset(periodic_ev, 0, sizeof(struct periodic_event));

    err = periodic_event_create(
        periodic_ev,
        get_default_waitset(),
        ENET_PERIODIC_SERVE_INTERVAL,
        MKCLOSURE(serve_periodic_events, state)
    );

    return err;
}

static errval_t enet_module_initialize(
    struct enet_driver_state *state
)
{
    errval_t err;

    assert(state != NULL);

    ENET_DEBUG("Initializing device...\n");
    err = enet_initialize_device(state);
    if (err_is_fail(err)) {
        debug_printf("Device initialization failed.\n");
        return err;
    }

    regionid_t rx_rid;
    regionid_t tx_rid;

    ENET_DEBUG("Initializing queues...\n");
    err = queues_initialize(state, &rx_rid, &tx_rid);
    if (err_is_fail(err)) {
        debug_printf("Queues initialization failed.\n");
        return err;
    }

    ENET_DEBUG("Initializing Ethernet state...\n");
    err = ethernet_initialize(
        &state->eth_state,
        state->mac,
        TX_RING_SIZE,
        state->tx_base,
        tx_rid,
        state->txq,
        udp_receive_cb
    );
    if (err_is_fail(err)) {
        debug_printf("Ethernet initialization failed.\n");
        return err;
    }

    ENET_DEBUG("Registering periodic events...\n");
    struct periodic_event periodic_ev;
    err = setup_periodic_events(&periodic_ev, state);
    if (err_is_fail(err)) {
        debug_printf("Cannot register periodic events.\n");
        return err;
    }

    ENET_DEBUG("Registering nameserver...\n");
    err = nameservice_register(
        NETWORKING_SERVICE_NAME,
        nameservice_receive_handler,
        state
    );
    if (err_is_fail(err)) {
        debug_printf("Cannot register nameservice callback.\n");
        return err;
    }

    return SYS_ERR_OK;
}

int main(
    int argc,
    char *argv[]
)
{
    errval_t err;

    debug_printf("ENET started.\n");

    struct enet_driver_state *state = calloc(1, sizeof(struct enet_driver_state));
    if (state == NULL) {
        debug_printf("Cannot claim memory for driver state.\n");
        return EXIT_FAILURE;
    }

    err = enet_module_initialize(state);
    if (err_is_fail(err)) {
        debug_printf("Driver initialization failed.\n");
        return EXIT_FAILURE;
    }

    debug_printf("Initialization complete.\n");

    ENET_DEBUG("MAC address is 0x%x.\n", state->mac);

    struct waitset *default_ws = get_default_waitset();

    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            debug_printf("Error while serving. Continuing...\n");
        }
    }

    return EXIT_SUCCESS;
}
