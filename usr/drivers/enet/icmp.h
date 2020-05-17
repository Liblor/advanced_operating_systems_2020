#ifndef __ICMP_H__
#define __ICMP_H__

#include <aos/aos.h>

#include "icmp.h"

struct ip_state;
struct ip_context;

struct icmp_state {
    uint16_t sequence_number;
    struct ip_state *ip_state;
};

enum icmp_type {
    ICMP_TYPE_ECHO_REQUEST,
    ICMP_TYPE_UNKNOWN,
};

errval_t icmp_initialize(
    struct icmp_state *state,
    struct ip_state *ip_state
);

errval_t icmp_process(
    struct icmp_state *state,
    const lvaddr_t base,
    const gensize_t size,
    const struct ip_context *context
);

#endif
