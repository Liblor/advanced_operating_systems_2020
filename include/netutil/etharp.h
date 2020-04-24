#ifndef _ETHARP_H_
#define _ETHARP_H_

#include <stdint.h>
#include <stddef.h>
#include <aos/aos.h>


//#define ETHARP_DEBUG_OPTION 1

#if defined(ETHARP_DEBUG_OPTION)
#define ETHARP_DEBUG(x...) debug_printf("[etharp] " x);
#else
#define ETHARP_DEBUG(fmt, ...) ((void)0)
#endif

#define ETH_HLEN 14     /* Default size for ip header */
#define ETH_CRC_LEN 4

#define ETH_TYPE(hdr)  ((hdr)->type)

#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IP 0x0800

#define ETH_ADDR_LEN 6

struct eth_addr {
    uint8_t addr[6];
} __attribute__((__packed__));

struct eth_hdr {
    struct eth_addr dst;
    struct eth_addr src;
    uint16_t type;
} __attribute__((__packed__));

#define ARP_HW_TYPE_ETH 0x1
#define ARP_PROT_IP 0x0800
#define ARP_OP_REQ 0x1
#define ARP_OP_REP 0x2
#define ARP_HLEN 28

struct arp_hdr {
    uint16_t hwtype;
    uint16_t proto;
    uint8_t hwlen;
    uint8_t protolen;
    uint16_t opcode;
    struct eth_addr eth_src;
    uint32_t ip_src;
    struct eth_addr eth_dst;
    uint32_t ip_dst;
} __attribute__((__packed__));



#endif
