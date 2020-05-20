#include <stdio.h>
#include <stdlib.h>

#include <aos/debug.h>
#include <aos/networking.h>

#define MY_DEFAULT_PORT (9000)

static void callback(
    const lvaddr_t payload,
    const gensize_t payload_size,
    const ip_addr_t ip,
    const udp_port_t port
)
{
}

int main(int argc, char *argv[])
{
    errval_t err;

    printf("Starting %s\n", argv[0]);

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

    /* TODO: When a UDP datagram is received, echo it to the sender. */

    err = networking_udp_register(
        port,
        callback
    );

    return EXIT_SUCCESS;
}
