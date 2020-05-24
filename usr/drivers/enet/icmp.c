#include "icmp.h"
#include "ip.h"

#include <aos/debug.h>
#include <netutil/icmp.h>
#include <netutil/checksum.h>

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

static errval_t icmp_reply(
    struct icmp_state *state,
    const ip_addr_t ip,
    const uint16_t identifier,
    const uint16_t sequence_number,
    const lvaddr_t base,
    const gensize_t size
)
{
    errval_t err;

    assert(state != NULL);
    assert((void *) base != NULL);

    const gensize_t total_size = sizeof(struct icmp_echo_hdr) + size;
    uint8_t buffer[total_size];
    memset(buffer, 0x00, total_size);

    struct icmp_echo_hdr *packet = (struct icmp_echo_hdr *) buffer;

    ICMPH_TYPE_SET(packet, ICMP_ER);
    ICMPH_CODE_SET(packet, 0);
    packet->id = identifier;
    packet->seqno = sequence_number;

    uint8_t *payload = buffer + sizeof(struct icmp_echo_hdr);
    memcpy(payload, (void *) base, size);

    /* As per RFC 792, for calculating the checksum, the checksum field is set
     * to zero. Note that the checksum is calculated over the full packet, thus
     * we need to adjust for the size. */
    packet->chksum = 0;
    const uint16_t checksum = inet_checksum(packet, total_size);
    packet->chksum = checksum;

    err = ip_send_packet(
        state->ip_state,
        IP_TYPE_ICMP,
        ip,
        (lvaddr_t) packet,
        total_size
    );
    if (err_is_fail(err)) {
        debug_printf("Cannot send IP packet.\n");
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    return SYS_ERR_OK;
}

static bool icmp_do_accept(
    struct icmp_state *state,
    struct icmp_echo_hdr *packet,
    const gensize_t size
)
{
    assert(state != NULL);
    assert(packet != NULL);

    /* TODO: Revisit this when implementing new types. */
    if (ICMPH_CODE(packet) != 0) {
        debug_printf("Code mismatch!\n");
        return false;
    }

    /* As per RFC 792, for calculating the checksum, the checksum field is set
     * to zero. Note that the checksum is calculated over the full packet, thus
     * we need to adjust for the size. */
    const uint16_t checksum_have = packet->chksum;
    packet->chksum = 0;
    const uint16_t checksum_want = inet_checksum(packet, size);

    if (checksum_have != checksum_want) {
        debug_printf("Checksum does not match! Have: 0x%04x, Want: 0x%04x\n", checksum_have, checksum_want);
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

errval_t icmp_process(
    struct icmp_state *state,
    const lvaddr_t base,
    const gensize_t size,
    const struct ip_context *context
)
{
    errval_t err;

    assert(state != NULL);
    assert(context != NULL);

    struct icmp_echo_hdr *packet = (struct icmp_echo_hdr *) base;

    if (!icmp_do_accept(state, packet, size)) {
        return SYS_ERR_OK;
    }

    const enum ip_type type = icmp_get_type(state, packet);

    switch (type) {
    case ICMP_TYPE_ECHO_REQUEST:
        ENET_ICMP_DEBUG("Packet is of type ECHO REQUEST.\n");

        const lvaddr_t payload = base + sizeof(struct icmp_echo_hdr);
        const gensize_t payload_size = size - sizeof(struct icmp_echo_hdr);

        err = icmp_reply(
            state,
            context->source,
            packet->id,
            packet->seqno,
            payload,
            payload_size
        );
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
