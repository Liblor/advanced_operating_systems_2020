#ifndef __ICMP_H__
#define __ICMP_H__

#include <aos/aos.h>

#include "icmp.h"

struct icmp_state {
    uint16_t sequence_number;
    struct ip_state *ip_state;
};

errval_t icmp_initialize(
    struct icmp_state *state,
    struct ip_state *ip_state
);

errval_t icmp_process(
    struct icmp_state *state,
    lvaddr_t base
);

#endif
