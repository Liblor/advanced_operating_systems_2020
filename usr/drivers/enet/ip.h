#ifndef __IP_H__
#define __IP_H__

#include <aos/aos.h>

#include "ethernet.h"

struct ip_state {
    uint32_t ip;
    struct ethernet_state *eth_state;
};

errval_t ip_initialize(
    struct ip_state *state,
    const uint32_t ip,
    struct ethernet_state *eth_state
);

errval_t ip_process(
    struct ip_state *state,
    lvaddr_t base
);

#endif
