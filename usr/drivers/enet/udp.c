#include "udp.h"
#include "ip.h"

#include <aos/debug.h>
#include <netutil/ip.h>
#include <netutil/udp.h>
#include <netutil/htons.h>

static void udp_release_binding(
    void *binding
)
{
    struct udp_binding *b = binding;
    debug_printf("Freeing binding for port %d\n", b->port);

    free(binding);
}

errval_t udp_initialize(
    struct udp_state *state,
    struct ip_state *ip_state,
    udp_receive_cb_t receive_cb
)
{
    assert(state != NULL);
    assert(ip_state != NULL);

    state->ip_state = ip_state;
    state->receive_cb = receive_cb;

    /* NOTE: This could fail if no more memory can be allocated. */
    collections_hash_create_with_buckets(&state->bindings, UDP_HASHTABLE_BUCKETS, udp_release_binding);

    return SYS_ERR_OK;
}

errval_t udp_send(
    struct udp_state *state,
    const lvaddr_t base,
    const gensize_t size,
    const udp_port_t source_port,
    const ip_addr_t ip,
    const udp_port_t port
)
{
    errval_t err;

    assert(state != NULL);
    assert((void *) base != NULL);

    const gensize_t total_size = sizeof(struct udp_hdr) + size;
    uint8_t buffer[total_size];
    memset(buffer, 0x00, total_size);

    struct udp_hdr *packet = (struct udp_hdr *) buffer;

    packet->src = htons(source_port);
    packet->dest = htons(port);
    packet->len = htons(total_size);

    /* As per RFC 768, the checksum can optionally be set to zero. */
    packet->chksum = 0;

    uint8_t *payload = buffer + sizeof(struct udp_hdr);
    memcpy(payload, (void *) base, size);

    err = ip_send_packet(
        state->ip_state,
        IP_TYPE_UDP,
        htonl(ip),
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
    //errval_t err;

    assert(state != NULL);
    assert((void *) base != NULL);
    assert(context != NULL);

    struct udp_hdr *packet = (struct udp_hdr *) base;

    if (!udp_do_accept(state, packet, size)) {
        return SYS_ERR_OK;
    }

    debug_printf("A valid UDP packet was received.\n");

    const lvaddr_t payload = base + sizeof(struct udp_hdr);
    const gensize_t payload_size = ntohs(packet->len) - sizeof(struct udp_hdr);
    const udp_port_t port = ntohs(packet->dest);

    struct udp_binding *binding = collections_hash_find(state->bindings, port);

    if (binding == NULL) {
        debug_printf("Cannot find binding for port %d.\n", port);
    } else {
        state->receive_cb(
            state,
            binding,
            payload,
            payload_size,
            ntohl(context->source),
            ntohs(packet->src)
        );
    }

    return SYS_ERR_OK;
}

errval_t udp_register(
    struct udp_state *state,
    const udp_port_t port,
    void *context
)
{
    //errval_t err;

    assert(state != NULL);
    assert(state->bindings);

    struct udp_binding *binding = collections_hash_find(state->bindings, port);

    if (binding != NULL) {
        return SYS_ERR_NOT_IMPLEMENTED;
    }

    debug_printf("Adding UDP binding for port %d.\n", port);

    binding = calloc(1, sizeof(struct udp_binding));
    if (binding == NULL) {
        debug_printf("calloc() failed\n");
        return LIB_ERR_MALLOC_FAIL;
    }

    binding->context = context;
    binding->port = port;

    collections_hash_insert(state->bindings, port, binding);

    return SYS_ERR_OK;
}

errval_t udp_deregister(
    struct udp_state *state,
    const udp_port_t port
)
{
    //errval_t err;

    assert(state != NULL);

    struct udp_binding *binding = collections_hash_find(state->bindings, port);

    if (binding == NULL) {
        return SYS_ERR_NOT_IMPLEMENTED;
    }

    debug_printf("Removing UDP binding for port %d.\n", port);

    collections_hash_delete(state->bindings, port);

    return SYS_ERR_OK;
}
