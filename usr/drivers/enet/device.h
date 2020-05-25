#ifndef __DEVICE_H__
#define __DEVICE_H__

#include <stdint.h>

#include <aos/aos.h>
#include <dev/imx8x/enet_dev.h>
#include <devif/queue_interface_backend.h>
#include <driverkit/driverkit.h>

void enet_read_mac(
    struct enet_driver_state *st
);

errval_t enet_init(
    struct enet_driver_state *st
);

errval_t enet_probe(
    struct enet_driver_state *st
);

#endif
