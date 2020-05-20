#ifndef __AOS_NETWORKING_H__
#define __AOS_NETWORKING_H__

#include <aos/aos.h>
#include <netutil/ip.h>
#include <aos/domain.h>

#define NETWORKING_SERVICE_NAME "networking"

typedef uint16_t udp_port_t;

typedef void (*networking_udp_cb_t)(
    const lvaddr_t payload,
    const gensize_t payload_size,
    const ip_addr_t ip,
    const udp_port_t port
);

enum networking_mtype {
    NETWORKING_MTYPE_UDP_REGISTER,
    NETWORKING_MTYPE_UDP_DEREGISTER,
    NETWORKING_MTYPE_UDP_SEND,
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

errval_t networking_udp_register(
    const udp_port_t port,
    networking_udp_cb_t callback
);

#endif
