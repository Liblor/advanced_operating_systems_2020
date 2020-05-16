#ifndef __IP_H__
#define __IP_H__

#include <aos/aos.h>

struct ethernet_state;

struct ip_state {
    struct ethernet_state *eth_state;
    uint32_t ip;
};

enum ip_type {
    IP_TYPE_ICMP,
    IP_TYPE_UDP,
    IP_TYPE_UNKNOWN,
};

errval_t ip_initialize(
    struct ip_state *state,
    struct ethernet_state *eth_state,
    const uint32_t ip
);

errval_t ip_process(
    struct ip_state *state,
    lvaddr_t base
);

#endif
