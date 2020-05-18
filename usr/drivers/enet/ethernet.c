#include "ethernet.h"
#include "enet.h"

#include <netutil/etharp.h>
#include <netutil/htons.h>

errval_t ethernet_initialize(
    struct ethernet_state *state,
    const uint64_t mac,
    const uint16_t tx_count,
    const lvaddr_t tx_base,
    const regionid_t tx_rid,
    struct enet_queue *tx_queue
)
{
    errval_t err;

    assert(state != NULL);

    state->mac = mac;
    state->tx_count = tx_count;
    state->tx_base = tx_base;
    state->tx_next = 0;
    state->tx_rid = tx_rid;
    state->tx_queue = tx_queue;

    state->tx_free = calloc(tx_count, sizeof(bool));
    if (state->tx_free == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    for (int i = 0; i < tx_count; i++) {
        state->tx_free[i] = true;
    }

    debug_printf("Initializing ARP state...\n");
    err = arp_initialize(&state->arp_state, state, mac, OWN_IP_ADDRESS);
    if (err_is_fail(err)) {
        debug_printf("ARP initialization failed.\n");
        return err;
    }

    debug_printf("Initializing IP state...\n");
    err = ip_initialize(&state->ip_state, state, OWN_IP_ADDRESS);
    if (err_is_fail(err)) {
        debug_printf("IP initialization failed.\n");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t ethernet_create(
    struct ethernet_state *state,
    const uint64_t receiver,
    const uint16_t type,
    lvaddr_t *base
)
{
    assert(state != NULL);
    assert(base != NULL);

    uint16_t index = state->tx_next;

    for (int i = 0; i < state->tx_count; i++) {
        if (state->tx_free[index] == true) {
            break;
        }

        index = (index + 1) % state->tx_count;
    }

    state->tx_next = (index + 1) % state->tx_count;

    if (state->tx_free[index] == false) {
        debug_printf("No free TX buffer available.\n");
        return SYS_ERR_NOT_IMPLEMENTED;
    }

    state->tx_free[index] = false;

    debug_printf("Found free buffer at index %d.\n", index);

    struct eth_hdr *eth_packet = (struct eth_hdr *) ((uint8_t *) state->tx_base + index * ENET_MAX_BUF_SIZE);

    to_eth_addr(&eth_packet->dst, receiver);
    to_eth_addr(&eth_packet->src, state->mac);
    eth_packet->type = htons(type);

    *base = (lvaddr_t) (((uint8_t *) eth_packet) + sizeof(struct eth_hdr));

    return SYS_ERR_OK;
}

errval_t ethernet_send(
    struct ethernet_state *state,
    const lvaddr_t base,
    const gensize_t size
)
{
    errval_t err;

    assert(state != NULL);
    assert((void *) base != NULL);

    debug_printf("Sending buffer of size 0x%zx.\n", size + sizeof(struct eth_hdr));

    /* TODO: Check if offset is in bounds. */
    const genoffset_t offset = base - state->tx_base - sizeof(struct eth_hdr);

    /* TODO: Check if valid length exceeds length. */
    struct devq_buf buf;
    buf.rid = state->tx_rid;
    buf.offset = offset;
    buf.length = ENET_MAX_BUF_SIZE;
    buf.valid_data = 0;
    buf.valid_length = sizeof(struct eth_hdr) + size;
    buf.flags = 0;

    err = devq_enqueue(
        (struct devq*) state->tx_queue,
        buf.rid,
        buf.offset,
        buf.length,
        buf.valid_data,
        buf.valid_length,
        buf.flags
    );
    if (err_is_fail(err)) {
        debug_printf("devq_enqueue() failed: %s\n", err_getstring(err));
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    while (true) {
        err = devq_dequeue(
            (struct devq *) state->tx_queue,
            &buf.rid,
            &buf.offset,
            &buf.length,
            &buf.valid_data,
            &buf.valid_length,
            &buf.flags
        );
        if (err_is_fail(err) && err_no(err) != DEVQ_ERR_QUEUE_EMPTY) {
            debug_printf("devq_dequeue() failed: %s\n", err_getstring(err));
            return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
        }
        if (err_is_ok(err)) {
            break;
        }

        thread_yield();
    };

    const genoffset_t index = offset / ENET_MAX_BUF_SIZE;
    assert(index < state->tx_count);

    state->tx_free[index] = true;

    return SYS_ERR_OK;
}

static bool ethernet_do_accept(
    struct ethernet_state *state,
    struct eth_hdr *packet
)
{
    assert(state != NULL);
    assert(packet != NULL);

    uint64_t receiver;
    from_eth_addr(&receiver, &packet->dst);

    if (receiver == state->mac ||
        receiver == ARP_BROADCAST_MAC) {
        return true;
    }

    return false;
}

static enum ethernet_type ethernet_get_type(
    struct ethernet_state *state,
    struct eth_hdr *packet
)
{
    assert(state != NULL);
    assert(packet != NULL);

    const uint16_t type = ntohs(ETH_TYPE(packet));

    switch (type) {
        case ETH_TYPE_ARP:
            return ETHERNET_TYPE_ARP;
            break;
        case ETH_TYPE_IP:
            return ETHERNET_TYPE_IPV4;
            break;
    }

    return ETHERNET_TYPE_UNKNOWN;
}

errval_t ethernet_process(
    struct ethernet_state *state,
    const lvaddr_t base,
    const gensize_t size
)
{
    errval_t err;

    assert(state != NULL);

    struct eth_hdr *packet = (struct eth_hdr *) base;

    if (!ethernet_do_accept(state, packet)) {
        return SYS_ERR_OK;
    }

    const enum ethernet_type type = ethernet_get_type(state, packet);
    const lvaddr_t newbase = base + sizeof(struct eth_hdr);
    const gensize_t newsize = size - sizeof(struct eth_hdr) - ETH_CRC_LEN;

    debug_printf("Ethernet packet payload has size %d.\n", newsize);

    switch (type) {
    case ETHERNET_TYPE_ARP:
        debug_printf("Packet is of type ARP.\n");

        err = arp_process(&state->arp_state, newbase);
        if (err_is_fail(err)) {
            debug_printf("arp_process() failed: %s\n", err_getstring(err));
            return err;
        }

        break;
    case ETHERNET_TYPE_IPV4:
        debug_printf("Packet is of type IPv4.\n");

        err = ip_process(&state->ip_state, newbase, newsize);
        if (err_is_fail(err)) {
            debug_printf("ip_process() failed: %s\n", err_getstring(err));
            return err;
        }

        break;
    default:
        debug_printf("Packet is of unknown type.\n");
        return SYS_ERR_OK;
    }

    return SYS_ERR_OK;
}
