#ifndef __UDP_H__
#define __UDP_H__

#include <aos/aos.h>

#include "udp.h"

struct ip_state;

struct udp_state {
    struct ip_state *ip_state;
};

errval_t udp_initialize(
    struct udp_state *state,
    struct ip_state *ip_state
);

errval_t udp_process(
    struct udp_state *state,
    lvaddr_t base
);

#endif
