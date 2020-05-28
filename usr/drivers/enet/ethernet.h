#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#include <stdint.h>

#include <aos/aos.h>
#include <dev/imx8x/enet_dev.h>
#include <devif/queue_interface_backend.h>
#include <driverkit/driverkit.h>

#include "arp.h"
#include "ip.h"

#define ENET_ETHERNET_DEBUG_OPTION 0

#if ENET_ETHERNET_DEBUG_OPTION
#define ENET_ETHERNET_DEBUG(x...) debug_printf("[enet/ethernet] " x);
#else
#define ENET_ETHERNET_DEBUG(fmt, ...) ((void)0)
#endif

#define ETHERNET_MAX_PAYLOAD (1500)
#define ETHERNET_DIGEST_LENGTH (17)

#define ARP_QUERY(eth_state, ip, mac) arp_query(&((eth_state)->arp_state), ip, mac)

struct ethernet_state {
    uint64_t mac;

    uint16_t tx_count;
    uint16_t tx_next;
    lvaddr_t tx_base;
    bool *tx_free;
    regionid_t tx_rid;
    struct enet_queue *tx_queue;

    struct arp_state arp_state;
    struct ip_state ip_state;
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
    struct enet_queue *tx_queue,
    udp_receive_cb_t udp_receive_cb
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

errval_t ethernet_process(
    struct ethernet_state *state,
    const lvaddr_t base,
    const gensize_t size
);

#endif
