#include <aos/networking.h>
#include <aos/nameserver.h>
#include <aos/domain.h>

errval_t networking_udp_register(
    const udp_port_t port,
    networking_udp_cb_t callback
)
{
    errval_t err;

    nameservice_chan_t chan;
    err = nameservice_lookup(
        NETWORKING_SERVICE_NAME,
        &chan
    );
    if (err_is_fail(err)) {
        debug_printf("nameservice_lookup() failed: %s\n", err_getstring(err));
        return err_push(err, SYS_ERR_NOT_IMPLEMENTED);
    }

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
        chan,
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
