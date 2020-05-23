#ifndef __IP_H__
#define __IP_H__

#include <aos/aos.h>
#include <netutil/ip.h>

#include "icmp.h"
#include "udp.h"

#define IP_DIGEST_LENGTH (15)

struct ethernet_state;

struct ip_state {
    struct ethernet_state *eth_state;
    ip_addr_t ip;

    struct icmp_state icmp_state;
    struct udp_state udp_state;
};

struct ip_context {
    ip_addr_t source;
};

enum ip_type {
    IP_TYPE_ICMP,
    IP_TYPE_UDP,
    IP_TYPE_UNKNOWN,
};

errval_t ip_initialize(
    struct ip_state *state,
    struct ethernet_state *eth_state,
    const ip_addr_t ip,
    udp_receive_cb_t udp_receive_cb
);

errval_t ip_send_packet(
    struct ip_state *state,
    const enum ip_type type,
    const ip_addr_t ip,
    const lvaddr_t base,
    const gensize_t size
);

errval_t ip_process(
    struct ip_state *state,
    const lvaddr_t base,
    const gensize_t size
);

#endif
