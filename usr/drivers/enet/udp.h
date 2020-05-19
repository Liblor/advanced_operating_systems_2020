#ifndef __UDP_H__
#define __UDP_H__

#include <aos/aos.h>
#include <netutil/ip.h>
#include <netutil/udp.h>

#include "udp.h"

#define UDP_HASHTABLE_BUCKETS (256)

struct ip_state;
struct ip_context;

struct udp_state {
    struct ip_state *ip_state;
    collections_hash_table *bindings;
};

typedef uint16_t udp_port_t;

errval_t udp_initialize(
    struct udp_state *state,
    struct ip_state *ip_state
);

errval_t udp_send(
    struct udp_state *state,
    const ip_addr_t ip,
    const udp_port_t port,
    const lvaddr_t base,
    const gensize_t size
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

#endif
