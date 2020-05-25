#ifndef __ROUTER_H__
#define __ROUTER_H__

#include <stdint.h>

#include <aos/aos.h>

#include "udp.h"

void nameservice_receive_handler(
    void *st,
    void *message,
    size_t bytes,
    void **response,
    size_t *response_bytes,
    struct capref tx_cap,
    struct capref *rx_cap
);

void udp_receive_cb(
    struct udp_state *state,
    struct udp_binding *binding,
    const lvaddr_t payload,
    const gensize_t payload_size,
    const ip_addr_t ip,
    const udp_port_t port
);

#endif
