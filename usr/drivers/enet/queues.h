#ifndef __QUEUES_H__
#define __QUEUES_H__

#include <aos/aos.h>
#include <dev/imx8x/enet_dev.h>
#include <devif/queue_interface_backend.h>
#include <driverkit/driverkit.h>

#include "enet.h"

errval_t queues_initialize(
    struct enet_driver_state *st,
    regionid_t *rx_rid,
    regionid_t *tx_rid
);

#endif
