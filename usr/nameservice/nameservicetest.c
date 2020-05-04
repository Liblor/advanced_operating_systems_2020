/**
 * \file
 * \brief init process for child spawning
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <aos/paging.h>
#include <aos/nameserver.h>


#define PANIC_IF_FAIL(err, msg)    \
    if (err_is_fail(err)) {        \
        USER_PANIC_ERR(err, msg);  \
    }

#define SERVICE_NAME "myservicename"
#define TEST_BINARY  "nameservicetest"
/*
 * ============================================================================
 * Client
 * ============================================================================
 */

static char *myrequest = "request !!";

static void run_client(void)
{
    errval_t err;

    /* look up service using name server */
    nameservice_chan_t chan;
    err = nameservice_lookup(SERVICE_NAME, &chan);
    PANIC_IF_FAIL(err, "failed to lookup service\n");

    debug_printf("Got the service %p. Sending request '%s'\n", chan, myrequest);

    void *request = myrequest;
    size_t request_size = strlen(myrequest);

    void *response;
    size_t response_bytes;
    err = nameservice_rpc(chan, request, request_size,
                          &response, &response_bytes,
                          NULL_CAP, NULL_CAP);
    PANIC_IF_FAIL(err, "failed to do the nameservice rpc\n");

    debug_printf("got response: %s\n", (char *)response);
}

/*
 * ============================================================================
 * Server
 * ============================================================================
 */

static char *myresponse = "reply!!";

static void server_recv_handler(void *st, void *message, 
                                size_t bytes,
                                void **response, size_t *response_bytes,
                                struct capref rx_cap, struct capref *tx_cap)
{
    debug_printf("server: got a request: %s\n", (char *)message);
    *response = myresponse;
    *response_bytes = strlen(myresponse);
}

static void run_server(void)
{
    errval_t err;

    debug_printf("register with nameservice '%s'\n", SERVICE_NAME);
    err = nameservice_register(SERVICE_NAME, server_recv_handler, NULL);
    PANIC_IF_FAIL(err, "failed to register...\n");

    domainid_t did;
    debug_printf("spawning test binary '%s'\n", TEST_BINARY);
    err = aos_rpc_process_spawn(get_init_rpc(), TEST_BINARY " a", disp_get_core_id(), &did);
    PANIC_IF_FAIL(err, "failed to spawn test\n");

    while(1) {
        event_dispatch(get_default_waitset());
    }
}

/*
 * ============================================================================
 * Main
 * ============================================================================
 */

int main(int argc, char *argv[])
{
    if (argc == 2) {
        debug_printf("nameservicetest: running client!\n");
        run_client();
    } else {
        debug_printf("nameservicetest: running server!\n");
        run_server();
    }

    return EXIT_SUCCESS;
}
