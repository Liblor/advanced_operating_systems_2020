#include <stdio.h>
#include <stdlib.h>

#include <aos/debug.h>
#include <aos/networking.h>

int main(int argc, char *argv[])
{
    errval_t err;

    switch (argc) {
    case 1:
        break;
    default:
        printf("Usage: %s\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("Querying ARP cache...\n");

    char *entries;
    err = networking_arp_list(&entries);
    assert(err_is_ok(err));

    printf("%s", entries);

    return EXIT_SUCCESS;
}
