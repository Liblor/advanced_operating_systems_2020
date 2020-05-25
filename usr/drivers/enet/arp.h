#ifndef __ARP_H__
#define __ARP_H__

#include <aos/aos.h>
#include <netutil/ip.h>

#define ENET_ARP_DEBUG_OPTION 1

#if ENET_ARP_DEBUG_OPTION
#define ENET_ARP_DEBUG(x...) debug_printf("[enet/arp] " x);
#else
#define ENET_ARP_DEBUG(fmt, ...) ((void)0)
#endif

#define ARP_HASHTABLE_BUCKETS (256)
#define ARP_CACHE_STRING_LINE_LENGTH (IP_DIGEST_LENGTH + ETHERNET_DIGEST_LENGTH + 4)
#define ARP_CACHE_STRING_LENGTH(x) (ARP_CACHE_STRING_LINE_LENGTH * x + 1)

struct ethernet_state;

struct arp_state {
    struct ethernet_state *eth_state;
    uint64_t mac;
    ip_addr_t ip;
    collections_hash_table *entries;
};

struct arp_entry {
    uint64_t mac;
};

enum arp_type {
    ARP_TYPE_REQUEST,
    ARP_TYPE_REPLY,
    ARP_TYPE_UNKNOWN,
};

errval_t arp_initialize(
    struct arp_state *state,
    struct ethernet_state *eth_state,
    const uint64_t mac,
    const ip_addr_t ip
);

errval_t arp_query(
    struct arp_state *state,
    const ip_addr_t ip,
    uint64_t *mac
);

errval_t arp_process(
    struct arp_state *state,
    lvaddr_t base
);

gensize_t arp_get_cache_size(
    struct arp_state *state
);

void arp_print_cache(
    struct arp_state *state,
    char *m
);

#endif
