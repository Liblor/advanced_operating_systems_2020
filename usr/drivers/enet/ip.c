#include "ip.h"
#include "ethernet.h"
#include "enet.h"

#include <netutil/etharp.h>
#include <netutil/htons.h>
#include <netutil/ip.h>
#include <netutil/checksum.h>

errval_t ip_initialize(
    struct ip_state *state,
    struct ethernet_state *eth_state,
    const uint32_t ip
)
{
    assert(state != NULL);
    assert(eth_state != NULL);

    state->eth_state = eth_state;
    state->ip = ip;

    return SYS_ERR_OK;
}

static bool ip_do_accept(
    struct ip_state *state,
    struct ip_hdr *packet
)
{
    assert(state != NULL);
    assert(packet != NULL);

    const uint16_t length = ntohs(packet->len);
    const bool flag_reserved = ntohs(packet->offset) & IP_RF;
    const bool flag_more_fragments = ntohs(packet->offset) & IP_MF;
    const bool offset = ntohs(packet->offset) & IP_OFFMASK;

    /* We store IP addresses in network byte-order. */
    const uint32_t destination = packet->dest;

    if (IPH_V(packet) != 4) {
        debug_printf("Implementation only supports IPv4!\n");
        return false;
    }
    if (IPH_HL(packet) != 5) {
        /* TODO: When implementing custom IHL, don't forget to adjust the
         * header checksum. */
        debug_printf("Custom IHL is not supported!\n");
        return false;
    }
    if (packet->tos != 0x00) {
        debug_printf("Custom DSCP/ECN is not supported!\n");
        return false;
    }
    /* Packets must be at least 20 bytes in size. */
    if (length < IP_HLEN) {
        debug_printf("Length is out of range!\n");
        return false;
    }
    if (flag_reserved) {
        debug_printf("Invalid packet: Reserved flag must not be set!\n");
        return false;
    }
    if (flag_more_fragments || offset > 0) {
        debug_printf("Fragmentation is not supported!\n");
        return false;
    }

    /* We need a copy to zero-out the checksum field. */
    struct ip_hdr header_copy;
    memcpy(&header_copy, packet, sizeof(header_copy));
    memset(&header_copy.chksum, 0, sizeof(header_copy.chksum));
    const uint16_t chksum = inet_checksum(&header_copy, sizeof(header_copy));

    if (packet->chksum != chksum) {
        debug_printf("Checksum does not match!\n");
        return false;
    }
    if (destination != state->ip) {
        debug_printf("Destination mismatch!\n");
        return false;
    }

    return true;
}

static enum ip_type ip_get_type(
    struct ip_state *state,
    struct ip_hdr *packet
)
{
    assert(state != NULL);
    assert(packet != NULL);

    const uint8_t type = packet->proto;

    switch (type) {
        case IP_PROTO_ICMP:
            return IP_TYPE_ICMP;
            break;
        case IP_PROTO_UDP:
            return IP_TYPE_UDP;
            break;
    }

    return IP_TYPE_UNKNOWN;
}

errval_t ip_process(
    struct ip_state *state,
    lvaddr_t base
)
{
    //errval_t err;

    assert(state != NULL);

    struct ip_hdr *packet = (struct ip_hdr *) base;

    if (ip_do_accept(state, packet)) {
        const enum ip_type type = ip_get_type(state, packet);
        //const lvaddr_t newbase = base + sizeof(struct ip_hdr);

        switch (type) {
        case IP_TYPE_ICMP:
            debug_printf("Packet is of type ICMP.\n");
            break;
        case IP_TYPE_UDP:
            debug_printf("Packet is of type UDP.\n");
            break;
        default:
            debug_printf("Packet is of unknown type.\n");
            return SYS_ERR_OK;
        }
    }

    return SYS_ERR_OK;
}
