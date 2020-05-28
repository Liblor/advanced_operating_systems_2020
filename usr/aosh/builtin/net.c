#include "net.h"
#include <stdio.h>
#include <stdlib.h>
#include <errors/errno.h>
#include <aos/networking.h>

#include "../aosh.h"

errval_t builtin_ip(int argc, char ** argv) {
    const ip_addr_t ip = NETWORKING_IP_ADDRESS;
    uint8_t *ip8 = (uint8_t *) &ip;

    printf(
        "%d.%d.%d.%d\n",
        ip8[0], ip8[1], ip8[2], ip8[3]
    );

    return SYS_ERR_OK;
}
