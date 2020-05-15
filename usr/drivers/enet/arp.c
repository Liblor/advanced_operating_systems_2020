#include "arp.h"
#include "ethernet.h"
#include "enet.h"

#include <netutil/etharp.h>
#include <netutil/htons.h>
#include <netutil/ip.h>

errval_t arp_initialize(
    struct arp_state *state,
    struct ethernet_state *eth_state,
    const uint64_t mac,
    const uint32_t ip
)
{
    assert(state != NULL);
    assert(eth_state != NULL);

    state->eth_state = eth_state;
    state->mac = mac;
    state->ip = ip;

    /* TODO: This could fail if no more memory can be allocated. */
    collections_hash_create_with_buckets(&state->entries, ARP_HASHTABLE_BUCKETS, NULL);

    return SYS_ERR_OK;
}

static errval_t arp_send_packet(
    struct arp_state *state,
    const uint64_t mac,
    const uint32_t ip,
    uint16_t opcode
)
{
    errval_t err;

    assert(state != NULL);

    struct arp_hdr *packet;
    err = ethernet_create(
        state->eth_state,
        mac,
        ETH_TYPE_ARP,
        (lvaddr_t *) &packet
    );
    if (err_is_fail(err)) {
        debug_printf("Cannot create Ethernet packet.\n");
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    packet->hwtype = htons(ARP_HW_TYPE_ETH);
    packet->proto = htons(ARP_PROT_IP);
    packet->hwlen = ETH_ADDR_LEN;
    packet->protolen = ARP_PLEN_IPV4;
    packet->opcode = htons(opcode);

    to_eth_addr(&packet->eth_src, state->mac);
    /* In a request, the THA field is ignored. */
    to_eth_addr(&packet->eth_dst, mac);

    packet->ip_src = state->ip;
    packet->ip_dst = ip;

    err = ethernet_send(
        state->eth_state,
        (lvaddr_t) packet,
        sizeof(struct arp_hdr)
    );
    if (err_is_fail(err)) {
        debug_printf("Cannot send Ethernet packet.\n");
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    return SYS_ERR_OK;
}

static errval_t arp_request(
    struct arp_state *state,
    const uint32_t ip
)
{
    errval_t err;

    assert(state != NULL);

    err = arp_send_packet(
        state,
        ARP_BROADCAST_MAC,
        ip,
        ARP_OP_REQ
    );
    if (err_is_fail(err)) {
        debug_printf("arp_send_packet() failed: %s\n", err_getstring(err));
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    return SYS_ERR_OK;
}

static errval_t arp_reply(
    struct arp_state *state,
    const uint64_t mac,
    const uint32_t ip
)
{
    errval_t err;

    assert(state != NULL);

    err = arp_send_packet(
        state,
        mac,
        ip,
        ARP_OP_REP
    );
    if (err_is_fail(err)) {
        debug_printf("arp_send_packet() failed: %s\n", err_getstring(err));
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    return SYS_ERR_OK;
}

errval_t arp_query(
    struct arp_state *state,
    const uint32_t ip,
    uint64_t *mac
)
{
    assert(state != NULL);
    assert(mac != NULL);

    struct arp_entry *entry = collections_hash_find(state->entries, ip);

    if (entry == NULL) {
        debug_printf("MAC address is not cached. Sending request...\n");

        arp_request(state, ip);

        /* TODO: Wait for the response, or store the request? */

        return SYS_ERR_NOT_IMPLEMENTED;
    } else {
        debug_printf("MAC address is cached.\n");
    }

    *mac = entry->mac;

    return SYS_ERR_OK;
}

static errval_t arp_register(
    struct arp_state *state,
    const uint32_t ip,
    const uint64_t mac
)
{
    assert(state != NULL);

    struct arp_entry *entry = collections_hash_find(state->entries, ip);

    if (entry == NULL) {
        entry = calloc(1, sizeof(struct arp_entry));
        if (entry == NULL) {
            debug_printf("calloc() failed\n");
            return LIB_ERR_MALLOC_FAIL;
        }

        debug_printf("Adding new ARP entry.\n");
        collections_hash_insert(state->entries, ip, entry);
    }

    entry->mac = mac;

    return SYS_ERR_OK;
}

errval_t arp_process(
    struct arp_state *state,
    lvaddr_t base
)
{
    errval_t err;

    assert(state != NULL);

    struct arp_hdr *packet = (struct arp_hdr *) base;

    if (packet->hwtype != htons(ARP_HW_TYPE_ETH)) {
        debug_printf("HTYPE mismatch!\n");
        return SYS_ERR_NOT_IMPLEMENTED;
    }
    if (packet->proto != htons(ARP_PROT_IP)) {
        debug_printf("PTYPE mismatch!\n");
        return SYS_ERR_NOT_IMPLEMENTED;
    }
    if (packet->hwlen != ETH_ADDR_LEN) {
        debug_printf("HLEN mismatch!\n");
        return SYS_ERR_NOT_IMPLEMENTED;
    }
    if (packet->protolen != ARP_PLEN_IPV4) {
        debug_printf("PLEN mismatch!\n");
        return SYS_ERR_NOT_IMPLEMENTED;
    }

    uint64_t eth_src;
    from_eth_addr(&eth_src, &packet->eth_src);

    /* Register the MAC address, no matter which operation was received. */
    err = arp_register(state, packet->ip_src, eth_src);
    if (err_is_fail(err)) {
        debug_printf("arp_register() failed: %s\n", err_getstring(err));
        return err;
    }

    switch (ntohs(packet->opcode)) {
    case ARP_OP_REQ:
        debug_printf("Received an ARP request.\n");

        if (packet->ip_dst == state->ip) {
            err = arp_reply(
                state,
                eth_src,
                packet->ip_src
            );
            if (err_is_fail(err)) {
                debug_printf("arp_reply() failed: %s\n", err_getstring(err));

                /* This error is not critical. */
                return SYS_ERR_OK;
            }
        }

        break;
    case ARP_OP_REP:
        debug_printf("Received an ARP reply.\n");
        break;
    default:
        debug_printf("Received unknown ARP operation.\n");
        break;
    }

    return SYS_ERR_OK;
}
