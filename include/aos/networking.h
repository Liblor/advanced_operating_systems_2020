#ifndef __AOS_NETWORKING_H__
#define __AOS_NETWORKING_H__

#include <aos/aos.h>
#include <netutil/ip.h>
#include <aos/domain.h>
#include <aos/nameserver.h>

#define NETWORKING_SERVICE_NAME "networking"
#define NETWORKING_IP_ADDRESS (MK_IP(2, 0, 0, 10))

typedef uint16_t udp_port_t;

typedef void (*networking_udp_cb_t)(
    const lvaddr_t payload,
    const gensize_t payload_size,
    const ip_addr_t from_ip,
    const udp_port_t from_port,
    const udp_port_t to_port
);

struct networking_state {
    nameservice_chan_t channel;
    networking_udp_cb_t udp_callback;
};

enum networking_mtype {
    NETWORKING_MTYPE_UDP_REGISTER,
    NETWORKING_MTYPE_UDP_DEREGISTER,
    NETWORKING_MTYPE_UDP_RECEIVE,
    NETWORKING_MTYPE_UDP_SEND,
    NETWORKING_MTYPE_ARP_LIST,
};

struct networking_message {
    enum networking_mtype type;
    gensize_t size;
    uint8_t payload[0];
};

struct networking_payload_udp_register {
    domainid_t pid;
    udp_port_t port;
};

struct networking_payload_udp_deregister {
    domainid_t pid;
    udp_port_t port;
};

struct networking_payload_udp_receive {
    ip_addr_t from_ip;
    udp_port_t from_port;
    udp_port_t to_port;
    gensize_t payload_size;
    uint8_t payload[0];
};

struct networking_payload_udp_send {
    ip_addr_t to_ip;
    udp_port_t to_port;
    udp_port_t from_port;
    gensize_t payload_size;
    uint8_t payload[0];
};

struct networking_payload_arp_list {
    char entries[0];
};

struct networking_state *get_current_networking_state(
    void
);

errval_t networking_init(
    struct networking_state *state,
    networking_udp_cb_t udp_callback
);

errval_t networking_udp_register(
    struct networking_state *state,
    const udp_port_t port
);

errval_t networking_udp_send(
    struct networking_state *state,
    const lvaddr_t payload,
    const gensize_t payload_size,
    const ip_addr_t to_ip,
    const udp_port_t to_port,
    const udp_port_t from_port
);

errval_t networking_arp_list(
    char **entries
);

#endif
