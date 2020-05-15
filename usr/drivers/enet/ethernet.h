#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#include <stdint.h>

#include <aos/aos.h>
#include <dev/imx8x/enet_dev.h>
#include <devif/queue_interface_backend.h>
#include <driverkit/driverkit.h>

struct ethernet_state {
    uint64_t mac;
    uint16_t tx_count;
    uint16_t tx_next;
    lvaddr_t tx_base;
    bool *tx_free;
    regionid_t tx_rid;
    struct enet_queue *tx_queue;
};

enum ethernet_type {
    ETHERNET_TYPE_ARP,
    ETHERNET_TYPE_IPV4,
    ETHERNET_TYPE_UNKNOWN,
};

errval_t ethernet_initialize(
    struct ethernet_state *state,
    const uint64_t mac,
    const uint16_t tx_count,
    const lvaddr_t tx_base,
    const regionid_t tx_rid,
    struct enet_queue *tx_queue
);

errval_t ethernet_create(
    struct ethernet_state *state,
    const uint64_t receiver,
    const uint16_t type,
    lvaddr_t *base
);

errval_t ethernet_send(
    struct ethernet_state *state,
    const lvaddr_t base,
    const gensize_t size
);

void ethernet_process(
    struct ethernet_state *state,
    const lvaddr_t base,
    bool *accept,
    enum ethernet_type *type,
    lvaddr_t *newbase
);

#endif
