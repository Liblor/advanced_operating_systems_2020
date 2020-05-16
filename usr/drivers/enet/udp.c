#include "udp.h"
#include "ip.h"

#include <aos/debug.h>

errval_t udp_initialize(
    struct udp_state *state,
    struct ip_state *ip_state
)
{
    assert(state != NULL);
    assert(ip_state != NULL);

    state->ip_state = ip_state;

    return SYS_ERR_OK;
}

errval_t udp_process(
    struct udp_state *state,
    lvaddr_t base
)
{
    //errval_t err;

    assert(state != NULL);

    //struct udp_hdr *packet = (struct udp_hdr *) base;

    debug_printf("A UDP packet was received.\n");

    return SYS_ERR_OK;
}
