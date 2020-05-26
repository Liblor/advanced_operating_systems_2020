/**
 * \file
 * \brief Hello world application
 */

/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */


#include <stdio.h>

#include <aos/aos.h>
#include <aos/debug.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <arch/aarch64/aos/dispatcher_arch.h>
#include <aos/deferred.h>


int main(int argc, char *argv[])
{
    printf("Printing hello in a loop\n");
    while(1) {
        struct dispatcher_generic *disp = get_dispatcher_generic(curdispatcher());
        domainid_t pid = disp->domain_id;
        printf("hello from %d\n", pid);
        barrelfish_usleep(1000 * 1000);
    }

    return EXIT_SUCCESS;
}
