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

errval_t ip_process(
    struct ip_state *state,
    lvaddr_t base
)
{
    //errval_t err;

    assert(state != NULL);

    struct ip_hdr *packet = (struct ip_hdr *) base;

    const uint16_t length = ntohs(packet->len);
    const bool flag_reserved = ntohs(packet->offset) & IP_RF;
    const bool flag_more_fragments = ntohs(packet->offset) & IP_MF;
    const bool offset = ntohs(packet->offset) & IP_OFFMASK;

    /* We store IP addresses in network byte-order. */
    const uint32_t destination = packet->dest;

    if (IPH_V(packet) != 4) {
        debug_printf("Implementation only supports IPv4!\n");
        return SYS_ERR_NOT_IMPLEMENTED;
    }
    if (IPH_HL(packet) != 5) {
        /* TODO: When implementing custom IHL, don't forget to adjust the
         * header checksum. */
        debug_printf("Custom IHL is not supported!\n");
        return SYS_ERR_NOT_IMPLEMENTED;
    }
    if (packet->tos != 0x00) {
        debug_printf("Custom DSCP/ECN is not supported!\n");
        return SYS_ERR_NOT_IMPLEMENTED;
    }
    /* Packets must be at least 20 bytes in size. */
    if (length < IP_HLEN) {
        debug_printf("Length is out of range!\n");
        return SYS_ERR_OK;
    }
    if (flag_reserved) {
        debug_printf("Invalid packet: Reserved flag must not be set!\n");
        return SYS_ERR_OK;
    }
    if (flag_more_fragments || offset > 0) {
        debug_printf("Fragmentation is not supported!\n");
        return SYS_ERR_NOT_IMPLEMENTED;
    }

    /* We need a copy to zero-out the checksum field. */
    struct ip_hdr header_copy;
    memcpy(&header_copy, packet, sizeof(header_copy));
    memset(&header_copy.chksum, 0, sizeof(header_copy.chksum));
    const uint16_t chksum = inet_checksum(&header_copy, sizeof(header_copy));

    if (packet->chksum != chksum) {
        debug_printf("Checksum does not match!\n");
        return SYS_ERR_OK;
    }
    if (destination != state->ip) {
        debug_printf("Destination mismatch!\n");
        return SYS_ERR_OK;
    }

    debug_printf("Received a valid IP packet!\n");

    return SYS_ERR_OK;
}
