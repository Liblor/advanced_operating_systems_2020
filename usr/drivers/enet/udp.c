#include "udp.h"
#include "ip.h"

#include <aos/debug.h>
#include <netutil/ip.h>
#include <netutil/udp.h>
#include <netutil/htons.h>

/* TODO: Remove this once dynamic ports are used. */
#define UDP_ECHO_PORT (9000)

errval_t udp_initialize(
    struct udp_state *state,
    struct ip_state *ip_state
)
{
    assert(state != NULL);
    assert(ip_state != NULL);

    state->ip_state = ip_state;

    return SYS_ERR_OK;
}

errval_t udp_send(
    struct udp_state *state,
    const ip_addr_t ip,
    const udp_port_t port,
    const lvaddr_t base,
    const gensize_t size
)
{
    errval_t err;

    assert(state != NULL);
    assert((void *) base != NULL);

    const gensize_t total_size = sizeof(struct udp_hdr) + size;
    uint8_t buffer[total_size];
    memset(buffer, 0x00, total_size);

    struct udp_hdr *packet = (struct udp_hdr *) buffer;

    packet->src = htons(UDP_ECHO_PORT);
    packet->dest = htons(port);
    packet->len = htons(total_size);

    /* As per RFC 768, the checksum can optionally be set to zero. */
    packet->chksum = 0;

    uint8_t *payload = buffer + sizeof(struct udp_hdr);
    memcpy(payload, (void *) base, size);

    err = ip_send_packet(
        state->ip_state,
        IP_TYPE_UDP,
        ip,
        (lvaddr_t) packet,
        total_size
    );
    if (err_is_fail(err)) {
        debug_printf("Cannot send IP packet.\n");
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    return SYS_ERR_OK;
}

static bool udp_do_accept(
    struct udp_state *state,
    struct udp_hdr *packet,
    const gensize_t size
)
{
    assert(state != NULL);
    assert(packet != NULL);

    debug_dump_mem((lvaddr_t) packet, (lvaddr_t) packet + size, 0);

    const lvaddr_t size_want = ntohs(packet->len);

    /* TODO: Sometimes, more data is sent than needed. Why? */
    if (size < size_want) {
        debug_printf("Size does not match! Have: 0x%04x, Want: 0x%04x\n", size, size_want);
        return false;
    }

    /* TODO: Verify the checksum. */

    return true;
}

errval_t udp_process(
    struct udp_state *state,
    const lvaddr_t base,
    const gensize_t size,
    const struct ip_context *context
)
{
    errval_t err;

    assert(state != NULL);
    assert(context != NULL);

    struct udp_hdr *packet = (struct udp_hdr *) base;

    if (!udp_do_accept(state, packet, size)) {
        return SYS_ERR_OK;
    }

    debug_printf("A valid UDP packet was received.\n");

    if (ntohs(packet->dest) == UDP_ECHO_PORT) {
        const lvaddr_t payload = base + sizeof(struct udp_hdr);
        const gensize_t payload_size = ntohs(packet->len) - sizeof(struct udp_hdr);

        err = udp_send(state, context->source, ntohs(packet->src), payload, payload_size);
        if (err_is_fail(err)) {
            debug_printf("udp_send() failed: %s\n", err_getstring(err));
            return err;
        }
    }

    return SYS_ERR_OK;
}
