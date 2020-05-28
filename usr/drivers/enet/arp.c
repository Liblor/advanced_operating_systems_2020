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
    const ip_addr_t ip
)
{
    assert(state != NULL);
    assert(eth_state != NULL);

    state->eth_state = eth_state;
    state->mac = mac;
    state->ip = ip;

    /* NOTE: This could fail if no more memory can be allocated. */
    collections_hash_create_with_buckets(&state->entries, ARP_HASHTABLE_BUCKETS, NULL);

    return SYS_ERR_OK;
}

static errval_t arp_send_packet(
    struct arp_state *state,
    const uint64_t mac,
    const ip_addr_t ip,
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
    const ip_addr_t ip
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
    const ip_addr_t ip
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
    const ip_addr_t ip,
    uint64_t *mac
)
{
    assert(state != NULL);
    assert(mac != NULL);

    struct arp_entry *entry = collections_hash_find(state->entries, ip);

    if (entry == NULL) {
        ENET_ARP_DEBUG("MAC address is not cached. Sending request...\n");

        arp_request(state, ip);

        return SYS_ERR_NOT_IMPLEMENTED;
    } else {
        ENET_ARP_DEBUG("MAC address is cached.\n");
    }

    *mac = entry->mac;

    return SYS_ERR_OK;
}

static errval_t arp_register(
    struct arp_state *state,
    const ip_addr_t ip,
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

        ENET_ARP_DEBUG("Adding new ARP entry.\n");
        collections_hash_insert(state->entries, ip, entry);
    }

    entry->mac = mac;

    return SYS_ERR_OK;
}

static bool arp_do_accept(
    struct arp_state *state,
    struct arp_hdr *packet
)
{
    assert(state != NULL);
    assert(packet != NULL);

    if (packet->hwtype != htons(ARP_HW_TYPE_ETH)) {
        debug_printf("HTYPE mismatch!\n");
        return false;
    }
    if (packet->proto != htons(ARP_PROT_IP)) {
        debug_printf("PTYPE mismatch!\n");
        return false;
    }
    if (packet->hwlen != ETH_ADDR_LEN) {
        debug_printf("HLEN mismatch!\n");
        return false;
    }
    if (packet->protolen != ARP_PLEN_IPV4) {
        debug_printf("PLEN mismatch!\n");
        return false;
    }

    return true;
}

static enum arp_type arp_get_type(
    struct arp_state *state,
    struct arp_hdr *packet
)
{
    assert(state != NULL);
    assert(packet != NULL);

    const uint8_t type = ntohs(packet->opcode);

    switch (type) {
        case ARP_OP_REQ:
            return ARP_TYPE_REQUEST;
            break;
        case ARP_OP_REP:
            return ARP_TYPE_REPLY;
            break;
    }

    return ARP_TYPE_UNKNOWN;
}

errval_t arp_process(
    struct arp_state *state,
    lvaddr_t base
)
{
    errval_t err;

    assert(state != NULL);

    struct arp_hdr *packet = (struct arp_hdr *) base;

    if (!arp_do_accept(state, packet)) {
        return SYS_ERR_OK;
    }

    uint64_t eth_src;
    from_eth_addr(&eth_src, &packet->eth_src);

    /* Register the MAC address, no matter which operation was received. */
    err = arp_register(state, packet->ip_src, eth_src);
    if (err_is_fail(err)) {
        debug_printf("arp_register() failed: %s\n", err_getstring(err));
        return err;
    }

    const enum arp_type type = arp_get_type(state, packet);

    switch (type) {
    case ARP_TYPE_REQUEST:
        ENET_ARP_DEBUG("Received an ARP request.\n");

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
    case ARP_TYPE_REPLY:
        ENET_ARP_DEBUG("Received an ARP reply.\n");
        break;
    default:
        debug_printf("Received unknown ARP operation.\n");
        break;
    }

    return SYS_ERR_OK;
}

gensize_t arp_get_cache_size(
    struct arp_state *state
)
{
    assert(state != NULL);

    return collections_hash_size(state->entries);
}

static genoffset_t arp_print_cache_addline(
    char *m,
    uint64_t ip,
    uint64_t mac
)
{
    uint8_t *eth8 = (uint8_t *) &mac;
    char ethernet_digest[ETHERNET_DIGEST_LENGTH + 1];
    snprintf(
        ethernet_digest, ETHERNET_DIGEST_LENGTH + 1, "%02x:%02x:%02x:%02x:%02x:%02x",
        eth8[5], eth8[4], eth8[3], eth8[2], eth8[1], eth8[0]
    );

    uint8_t *ip8 = (uint8_t *) &ip;
    char ip_digest[IP_DIGEST_LENGTH + 1];
    snprintf(
        ip_digest, IP_DIGEST_LENGTH + 1, "%d.%d.%d.%d",
        ip8[0], ip8[1], ip8[2], ip8[3]
    );

    int written = snprintf(m, ARP_CACHE_STRING_LINE_LENGTH, "%s - %s", ethernet_digest, ip_digest);
    m[written] = ' ';
    m[ARP_CACHE_STRING_LINE_LENGTH - 1] = '\n';

    return ARP_CACHE_STRING_LINE_LENGTH;
}

void arp_print_cache(
    struct arp_state *state,
    char *m
)
{
    int32_t ret;

    assert(state != NULL);

    gensize_t cache_size = arp_get_cache_size(state);
    gensize_t string_size = ARP_CACHE_STRING_LENGTH(cache_size);

    memset(m, ' ', string_size);

    genoffset_t position = 0;

    position += arp_print_cache_addline(m + position, state->ip, state->mac);
    debug_printf("position=%d,mac:%d\n", position, state->mac);

    ret = collections_hash_traverse_start(state->entries);
    assert(ret == 1);

    struct arp_entry *entry;
    uint64_t key;

    while ((entry = collections_hash_traverse_next(state->entries, &key)) != NULL) {
        position += arp_print_cache_addline(m + position, key, entry->mac);
        debug_printf("position=%d,mac:%d\n", position, entry->mac);
    }

    ret = collections_hash_traverse_end(state->entries);
    assert(ret == 1);

    m[string_size - 1] = '\0';

    debug_dump_mem((lvaddr_t) m, (lvaddr_t) m + string_size, 0);
}
