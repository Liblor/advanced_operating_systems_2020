#ifndef __ARP_H__
#define __ARP_H__

#include <aos/aos.h>

#define ARP_HASHTABLE_BUCKETS (256)

struct ethernet_state;

struct arp_state {
    struct ethernet_state *eth_state;
    uint64_t mac;
    uint32_t ip;
    collections_hash_table *entries;
};

struct arp_entry {
    uint64_t mac;
};

errval_t arp_initialize(
    struct arp_state *state,
    struct ethernet_state *eth_state,
    const uint64_t mac,
    const uint32_t ip
);

errval_t arp_query(
    struct arp_state *state,
    const uint32_t ip,
    uint64_t *mac
);

errval_t arp_process(
    struct arp_state *state,
    lvaddr_t base
);

#endif
