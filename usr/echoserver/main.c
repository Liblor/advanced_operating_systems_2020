#include <stdio.h>
#include <stdlib.h>

#include <aos/debug.h>
#include <aos/networking.h>

#define MY_DEFAULT_PORT (9000)

static void callback(
    const lvaddr_t payload,
    const gensize_t payload_size,
    const ip_addr_t from_ip,
    const udp_port_t from_port,
    const udp_port_t to_port
)
{
    errval_t err;

    debug_printf("echo: %s", (char *) payload);

    err = networking_udp_send(
        get_current_networking_state(),
        payload,
        payload_size,
        from_ip,
        from_port,
        to_port
    );
    if (err_is_fail(err)) {
        debug_printf("networking_udp_send() failed: %s\n", err_getstring(err));
    }
}

int main(int argc, char *argv[])
{
    errval_t err;

    udp_port_t port;

    switch (argc) {
    case 1:
        port = MY_DEFAULT_PORT;
        break;
    case 2:
        port = strtol(argv[1], NULL, 10);
        break;
    default:
        printf("Usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("Listening for UDP packets on port %d...\n", port);

    err = networking_init(
        get_current_networking_state(),
        callback
    );
    assert(err_is_ok(err));

    err = networking_udp_register(
        get_current_networking_state(),
        port
    );
    assert(err_is_ok(err));

    struct waitset *default_ws = get_default_waitset();

    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            debug_printf("Error while serving. Continuing...\n");
        }
    }

    return EXIT_SUCCESS;
}
