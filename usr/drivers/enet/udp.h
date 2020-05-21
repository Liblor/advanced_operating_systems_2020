#ifndef __UDP_H__
#define __UDP_H__

#include <aos/aos.h>
#include <aos/networking.h>

#include <netutil/ip.h>
#include <netutil/udp.h>

#include "udp.h"

#define UDP_HASHTABLE_BUCKETS (256)

struct udp_binding {
    void *context;
    udp_port_t port;
};

struct udp_state;

typedef void (*udp_receive_cb_t)(
    struct udp_state *state,
    struct udp_binding *binding,
    const lvaddr_t payload,
    const gensize_t payload_size,
    const ip_addr_t ip,
    const udp_port_t port
);

struct ip_state;
struct ip_context;

struct udp_state {
    struct ip_state *ip_state;
    udp_receive_cb_t receive_cb;
    collections_hash_table *bindings;
};

errval_t udp_initialize(
    struct udp_state *state,
    struct ip_state *ip_state,
    udp_receive_cb_t receive_cb
);

errval_t udp_send(
    struct udp_state *state,
    const lvaddr_t base,
    const gensize_t size,
    const udp_port_t source_port,
    const ip_addr_t ip,
    const udp_port_t port
);

errval_t udp_process(
    struct udp_state *state,
    const lvaddr_t base,
    const gensize_t size,
    const struct ip_context *context
);

errval_t udp_register(
    struct udp_state *state,
    const udp_port_t port,
    void *context
);

errval_t udp_deregister(
    struct udp_state *state,
    const udp_port_t port
);

#endif
