#include <aos/networking.h>
#include <aos/nameserver.h>
#include <aos/domain.h>

static struct networking_state curr_state;

struct networking_state *get_current_networking_state(
    void
)
{
    return &curr_state;
}

static void nameservice_receive_handler(
    void *st,
    void *message,
    size_t bytes,
    void **response,
    size_t *response_bytes,
    struct capref tx_cap,
    struct capref *rx_cap
)
{
    struct networking_state *state = st;
    struct networking_message *net_message = (struct networking_message *) message;

    const enum networking_mtype type = net_message->type;

    /* Could not do the assignment in a switch block... */
    if (type == NETWORKING_MTYPE_UDP_RECEIVE) {
        struct networking_payload_udp_receive *tsp = (struct networking_payload_udp_receive *) net_message->payload;

        state->udp_callback(
            (lvaddr_t) tsp->payload,
            tsp->payload_size,
            tsp->from_ip,
            tsp->from_port,
            tsp->to_port
        );
    } else {
        debug_printf("Received unknown type in nameservice receive handler.\n");
    }
}

errval_t networking_init(
    struct networking_state *state,
    networking_udp_cb_t udp_callback
)
{
    errval_t err;

    state->udp_callback = udp_callback;

    err = nameservice_lookup(
        NETWORKING_SERVICE_NAME,
        &state->channel
    );
    if (err_is_fail(err)) {
        debug_printf("nameservice_lookup() failed: %s\n", err_getstring(err));
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    const domainid_t mypid = disp_get_domain_id();

    char service_name[16];
    snprintf(service_name, sizeof(service_name), "pid%d", mypid);

    err = nameservice_register(
        service_name,
        nameservice_receive_handler,
        state
    );
    if (err_is_fail(err)) {
        debug_printf("nameservice_register() failed: %s\n", err_getstring(err));
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    return SYS_ERR_OK;
}

errval_t networking_udp_register(
    struct networking_state *state,
    const udp_port_t port
)
{
    errval_t err;

    const domainid_t mypid = disp_get_domain_id();

    struct networking_payload_udp_register payload = {
        .pid = mypid,
        .port = port,
    };

    const gensize_t size = sizeof(struct networking_message) + sizeof(payload);
    uint8_t buffer[size];
    struct networking_message *message = (struct networking_message *) buffer;

    message->type = NETWORKING_MTYPE_UDP_REGISTER;
    message->size = sizeof(payload);
    memcpy(message->payload, &payload, sizeof(payload));

    err = nameservice_rpc(
        state->channel,
        message,
        size,
        NULL,
        NULL,
        NULL_CAP,
        NULL_CAP
    );
    if (err_is_fail(err)) {
        debug_printf("nameservice_rpc() failed: %s\n", err_getstring(err));
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    return SYS_ERR_OK;
}

errval_t networking_udp_send(
    struct networking_state *state,
    const lvaddr_t payload,
    const gensize_t payload_size,
    const ip_addr_t to_ip,
    const udp_port_t to_port,
    const udp_port_t from_port
)
{
    errval_t err;

    const gensize_t tsp_size = sizeof(struct networking_payload_udp_send) + payload_size;
    uint8_t tsp_buffer[tsp_size];
    struct networking_payload_udp_send *tsp = (struct networking_payload_udp_send *) tsp_buffer;

    tsp->to_ip = to_ip;
    tsp->to_port = to_port;
    tsp->from_port = from_port;
    tsp->payload_size = payload_size;
    memcpy(tsp->payload, (void *) payload, payload_size);

    const gensize_t size = sizeof(struct networking_message) + tsp_size;
    uint8_t buffer[size];
    struct networking_message *message = (struct networking_message *) buffer;

    message->type = NETWORKING_MTYPE_UDP_SEND;
    message->size = tsp_size;
    memcpy(message->payload, tsp, tsp_size);

    err = nameservice_rpc(
        state->channel,
        message,
        size,
        NULL,
        NULL,
        NULL_CAP,
        NULL_CAP
    );
    if (err_is_fail(err)) {
        debug_printf("nameservice_rpc() failed: %s\n", err_getstring(err));
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    return SYS_ERR_OK;
}

errval_t networking_arp_list(
    char **entries
)
{
    errval_t err;

    assert(entries != NULL);
    *entries = NULL;

    nameservice_chan_t channel;

    err = nameservice_lookup(
        NETWORKING_SERVICE_NAME,
        &channel
    );
    if (err_is_fail(err)) {
        debug_printf("nameservice_lookup() failed: %s\n", err_getstring(err));
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    const gensize_t size = sizeof(struct networking_message);
    uint8_t buffer[size];
    struct networking_message *message = (struct networking_message *) buffer;

    message->type = NETWORKING_MTYPE_ARP_LIST;
    message->size = 0;

    struct networking_message *response;
    size_t response_size;

    err = nameservice_rpc(
        channel,
        message,
        size,
        (void **) &response,
        &response_size,
        NULL_CAP,
        NULL_CAP
    );
    if (err_is_fail(err)) {
        debug_printf("nameservice_rpc() failed: %s\n", err_getstring(err));
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

    struct networking_payload_arp_list *tsp = (struct networking_payload_arp_list *) response->payload;

    *entries = tsp->entries;

    return SYS_ERR_OK;
}
