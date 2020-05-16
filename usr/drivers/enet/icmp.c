#include "icmp.h"
#include "ip.h"

#include <aos/debug.h>
#include <netutil/icmp.h>

errval_t icmp_initialize(
    struct icmp_state *state,
    struct ip_state *ip_state
)
{
    assert(state != NULL);
    assert(ip_state != NULL);

    state->sequence_number = 0;
    state->ip_state = ip_state;

    return SYS_ERR_OK;
}

errval_t icmp_process(
    struct icmp_state *state,
    lvaddr_t base
)
{
    //errval_t err;

    assert(state != NULL);

    //struct icmp_echo_hdr *packet = (struct icmp_echo_hdr *) base;

    debug_printf("An ICMP packet was received.\n");

    return SYS_ERR_OK;
}
