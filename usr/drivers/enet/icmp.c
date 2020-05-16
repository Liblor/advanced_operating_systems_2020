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

static bool icmp_do_accept(
    struct icmp_state *state,
    struct icmp_echo_hdr *packet
)
{
    assert(state != NULL);
    assert(packet != NULL);

    /* TODO: Revisit this when implementing new types. */
    if (ICMPH_CODE(packet) != 0) {
        debug_printf("Code mismatch!\n");
        return false;
    }

    return true;
}

static enum icmp_type icmp_get_type(
    struct icmp_state *state,
    struct icmp_echo_hdr *packet
)
{
    assert(state != NULL);
    assert(packet != NULL);

    const uint8_t type = ICMPH_TYPE(packet);

    switch (type) {
        case ICMP_ECHO:
            return ICMP_TYPE_ECHO_REQUEST;
            break;
    }

    return ICMP_TYPE_UNKNOWN;
}

static errval_t icmp_reply(
    struct icmp_state *state,
    const ip_addr_t ip
)
{
    //errval_t err;

    assert(state != NULL);

    debug_printf("Sending ICMP ECHO REPLY to %d.\n", ip);

    return SYS_ERR_OK;
}

errval_t icmp_process(
    struct icmp_state *state,
    const lvaddr_t base,
    const struct ip_context *context
)
{
    errval_t err;

    assert(state != NULL);

    struct icmp_echo_hdr *packet = (struct icmp_echo_hdr *) base;

    if (!icmp_do_accept(state, packet)) {
        return SYS_ERR_OK;
    }

    const enum ip_type type = icmp_get_type(state, packet);

    switch (type) {
    case ICMP_TYPE_ECHO_REQUEST:
        debug_printf("Packet is of type ECHO REQUEST.\n");

        err = icmp_reply(state, context->source);
        if (err_is_fail(err)) {
            debug_printf("icmp_reply() failed: %s\n", err_getstring(err));
            return err;
        }

        break;
    default:
        debug_printf("Packet is of unknown type.\n");
        return SYS_ERR_OK;
    }

    return SYS_ERR_OK;
}
