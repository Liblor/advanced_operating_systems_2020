#include "ip.h"
#include "ethernet.h"
#include "enet.h"

#include <aos/debug.h>
#include <netutil/etharp.h>
#include <netutil/htons.h>
#include <netutil/ip.h>
#include <netutil/checksum.h>

errval_t ip_initialize(
    struct ip_state *state,
    struct ethernet_state *eth_state,
    const ip_addr_t ip
)
{
    errval_t err;

    assert(state != NULL);
    assert(eth_state != NULL);

    state->eth_state = eth_state;
    state->ip = ip;

    debug_printf("Initializing ICMP state...\n");
    err = icmp_initialize(&state->icmp_state, state);
    if (err_is_fail(err)) {
        debug_printf("ICMP initialization failed.\n");
        return err;
    }

    debug_printf("Initializing UDP state...\n");
    err = udp_initialize(&state->udp_state, state);
    if (err_is_fail(err)) {
        debug_printf("UDP initialization failed.\n");
        return err;
    }

    return SYS_ERR_OK;
}

static uint8_t ip_type_to_value(
    const enum ip_type type
)
{
    switch (type) {
        case IP_TYPE_ICMP:
            return IP_PROTO_ICMP;
            break;
        case IP_TYPE_UDP:
            return IP_PROTO_UDP;
            break;
        default:
            break;
    }

    /* TODO: Raise an error instead? */
    return 0;
}

errval_t ip_send_packet(
    struct ip_state *state,
    const enum ip_type type,
    const ip_addr_t ip,
    const lvaddr_t base,
    const gensize_t size
)
{
    errval_t err;

    assert(state != NULL);

    if (size > ETHERNET_MAX_PAYLOAD) {
        debug_printf("Size exceeds MTU.\n", ip);
        return SYS_ERR_NOT_IMPLEMENTED;
    }

    uint64_t mac;
    err = ARP_QUERY(state->eth_state, ip, &mac);
    if (err_is_fail(err)) {
        debug_printf("Cannot retrieve MAC address for IP 0x%08x.\n", ip);
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    struct ip_hdr *packet;
    err = ethernet_create(
        state->eth_state,
        mac,
        ETH_TYPE_IP,
        (lvaddr_t *) &packet
    );
    if (err_is_fail(err)) {
        debug_printf("Cannot create Ethernet packet.\n");
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    IPH_VHL_SET(packet, 4, 5);
    packet->tos = 0;
    packet->len = htons(sizeof(struct ip_hdr) + size);
    packet->id = 0;
    packet->offset = htons(IP_DF);
    packet->ttl = 64;
    packet->proto = ip_type_to_value(type);
    packet->src = state->ip;
    packet->dest = ip;

    packet->chksum = 0;
    const uint16_t checksum = inet_checksum(packet, sizeof(struct ip_hdr));
    packet->chksum = checksum;

    /* Copy the payload. */
    uint8_t *payload = (uint8_t *) packet + sizeof(struct ip_hdr);
    memcpy(payload, (void *) base, size);

    err = ethernet_send(
        state->eth_state,
        (lvaddr_t) packet,
        sizeof(struct ip_hdr) + size
    );
    if (err_is_fail(err)) {
        debug_printf("Cannot send Ethernet packet.\n");
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

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
    /* TODO: Check if this matches the transmitted size. */
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
    packet->chksum = 0;
    const uint16_t checksum = inet_checksum(packet, sizeof(struct ip_hdr));
    packet->chksum = checksum;

    if (packet->chksum != checksum) {
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
    const lvaddr_t base,
    const gensize_t size
)
{
    errval_t err;

    assert(state != NULL);

    struct ip_hdr *packet = (struct ip_hdr *) base;

    const struct ip_context context = {
        .source = packet->src,
    };

    if (!ip_do_accept(state, packet)) {
        return SYS_ERR_OK;
    }

    const enum ip_type type = ip_get_type(state, packet);
    const lvaddr_t newbase = base + sizeof(struct ip_hdr);
    const gensize_t newsize = size - sizeof(struct ip_hdr);

    debug_printf("IP packet payload has size %d.\n", newsize);

    switch (type) {
    case IP_TYPE_ICMP:
        debug_printf("Packet is of type ICMP.\n");

        err = icmp_process(&state->icmp_state, newbase, newsize, &context);
        if (err_is_fail(err)) {
            debug_printf("icmp_process() failed: %s\n", err_getstring(err));
            return err;
        }

        break;
    case IP_TYPE_UDP:
        debug_printf("Packet is of type UDP.\n");

        err = udp_process(&state->udp_state, newbase, newsize, &context);
        if (err_is_fail(err)) {
            debug_printf("udp_process() failed: %s\n", err_getstring(err));
            return err;
        }

        break;
    default:
        debug_printf("Packet is of unknown type.\n");
        return SYS_ERR_OK;
    }

    return SYS_ERR_OK;
}
