#include <strings.h>

#include "enet.h"
#include "router.h"

void nameservice_receive_handler(
    void *st,
    void *message,
    size_t bytes,
    void **response,
    size_t *response_bytes,
    struct capref tx_cap,
    struct capref *rx_cap
)
{
    errval_t err;

    struct enet_driver_state *state = st;
    struct networking_message *net_message = (struct networking_message *) message;

    assert(state != NULL);
    assert(net_message != NULL);

    const enum networking_mtype type = net_message->type;

    /* Could not do the assignment in a switch block... */
    if (type == NETWORKING_MTYPE_UDP_SEND) {
        struct networking_payload_udp_send *tsp = (struct networking_payload_udp_send *) net_message->payload;
        assert(tsp != NULL);

        err = udp_send(
            &state->eth_state.ip_state.udp_state,
            (lvaddr_t) tsp->payload,
            tsp->payload_size,
            tsp->from_port,
            tsp->to_ip,
            tsp->to_port
        );
        if (err_is_fail(err)) {
            debug_printf("udp_send() failed: %s\n", err_getstring(err));
            return;
        }
    } else if (type == NETWORKING_MTYPE_UDP_REGISTER) {
        struct networking_payload_udp_register *tsp = (struct networking_payload_udp_register *) net_message->payload;
        assert(tsp != NULL);

        char service_name[16];
        snprintf(service_name, sizeof(service_name), "pid%d", tsp->pid);

        nameservice_chan_t channel;

        err = nameservice_lookup(
            service_name,
            &channel
        );
        if (err_is_fail(err)) {
            debug_printf("nameservice_lookup() failed: %s\n", err_getstring(err));
            return;
        }

        err = udp_register(&state->eth_state.ip_state.udp_state, tsp->port, channel);
        if (err_is_fail(err)) {
            debug_printf("Cannot register UDP receive callback.\n");
            return;
        }
    } else if (type == NETWORKING_MTYPE_ARP_LIST) {
        if (net_message->size != 0) {
            debug_printf("Length must be 0.\n");
            return;
        }
        if (response == NULL || response_bytes == NULL) {
            debug_printf("No response pointer passed!\n");
            return;
        }

        const gensize_t cache_size = arp_get_cache_size(&state->eth_state.arp_state);
        const gensize_t entries_length = ARP_CACHE_STRING_LENGTH(cache_size);

        const gensize_t size = sizeof(struct networking_message) + entries_length;
        struct networking_message *net_response = calloc(1, size);

        struct networking_payload_arp_list *tsp_response = (struct networking_payload_arp_list *) net_response->payload;

        arp_print_cache(&state->eth_state.arp_state, tsp_response->entries);

        *response = net_response;
        *response_bytes = size;
    } else {
        debug_printf("Received unknown type in nameservice receive handler.\n");
        return;
    }
}

void udp_receive_cb(
    struct udp_state *state,
    struct udp_binding *binding,
    const lvaddr_t payload,
    const gensize_t payload_size,
    const ip_addr_t ip,
    const udp_port_t port
)
{
    errval_t err;

    assert(state != NULL);
    assert(binding != NULL);

    const gensize_t tsp_size = sizeof(struct networking_payload_udp_receive) + payload_size;
    uint8_t tsp_buffer[tsp_size];
    struct networking_payload_udp_receive *tsp = (struct networking_payload_udp_receive *) tsp_buffer;

    tsp->from_ip = ip;
    tsp->from_port = port;
    tsp->to_port = binding->port;
    tsp->payload_size = payload_size;
    memcpy(tsp->payload, (void *) payload, payload_size);

    const gensize_t size = sizeof(struct networking_message) + tsp_size;
    uint8_t buffer[size];
    struct networking_message *message = (struct networking_message *) buffer;

    message->type = NETWORKING_MTYPE_UDP_RECEIVE;
    message->size = tsp_size;
    memcpy(message->payload, tsp, tsp_size);

    err = nameservice_rpc(
        binding->context,
        message,
        size,
        NULL,
        NULL,
        NULL_CAP,
        NULL_CAP
    );
    if (err_is_fail(err)) {
        debug_printf("nameservice_rpc() failed: %s\n", err_getstring(err));
    }
}
