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

#define SERVICE_NAME "test"
#define TEST_BINARY  "nameservicetest"
/*
 * ============================================================================
 * Client
 * ============================================================================
 */

static char *myrequest = "request !!";

static void test_query(char *query)
{
    errval_t err;

    size_t num;
    char *result = NULL;
    err = nameservice_enumerate(query, &num, &result);
    PANIC_IF_FAIL(err, "failed to do the nameservice enumerate\n");

    debug_printf("got enumeration for query '%s':\n", query);
    char *name = result;
    for (int i = 0; i < num; i++) {
        size_t name_len = strlen(name);
        debug_printf("found match '%s'\n", name);
        name += name_len + 1;
    }
}

static void test_lookup(char *name) {
    errval_t err;

    debug_printf("Testing lookup for %s\n", name);

    nameservice_chan_t chan;
    err = nameservice_lookup(name, &chan);
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

static void run_client(void)
{
    test_query("");
    test_query("t");
    test_query(SERVICE_NAME);
    test_query(SERVICE_NAME "/asdf");
    test_query(SERVICE_NAME "/bla");
    test_query(SERVICE_NAME "/bla1");
    test_query(SERVICE_NAME "/bla3");
    test_query(SERVICE_NAME "/bla32");

    test_lookup(SERVICE_NAME);
    test_lookup(SERVICE_NAME"/bla");
    test_lookup(SERVICE_NAME"/bla1");
    test_lookup(SERVICE_NAME"/bla12");
    test_lookup(SERVICE_NAME"/bla31");
    test_lookup(SERVICE_NAME"/bla32");
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
    size_t len = strlen(myresponse) + 1;
    *response = malloc(len);
    strcpy(*response, myresponse);
    *response_bytes = len;
}

static void run_server(void)
{
    errval_t err;

    debug_printf("register with nameservice '%s'\n", SERVICE_NAME);
    err = nameservice_register(SERVICE_NAME, server_recv_handler, NULL);
    PANIC_IF_FAIL(err, "failed to register...\n");

    debug_printf("register with nameservice '%s'\n", SERVICE_NAME"/bla");
    err = nameservice_register(SERVICE_NAME"/bla", server_recv_handler, NULL);
    PANIC_IF_FAIL(err, "failed to register...\n");

    debug_printf("register with nameservice '%s'\n", SERVICE_NAME"/bla1");
    err = nameservice_register(SERVICE_NAME"/bla1", server_recv_handler, NULL);
    PANIC_IF_FAIL(err, "failed to register...\n");

    debug_printf("register with nameservice '%s'\n", SERVICE_NAME"/bla12");
    err = nameservice_register(SERVICE_NAME"/bla12", server_recv_handler, NULL);
    PANIC_IF_FAIL(err, "failed to register...\n");

    debug_printf("register with nameservice '%s'\n", SERVICE_NAME"/bla31");
    err = nameservice_register(SERVICE_NAME"/bla31", server_recv_handler, NULL);
    PANIC_IF_FAIL(err, "failed to register...\n");

    debug_printf("register with nameservice '%s'\n", SERVICE_NAME"/bla32");
    err = nameservice_register(SERVICE_NAME"/bla32", server_recv_handler, NULL);
    PANIC_IF_FAIL(err, "failed to register...\n");

    err = nameservice_deregister(SERVICE_NAME);
    PANIC_IF_FAIL(err, "failed to deregister...\n");

    err = nameservice_register(SERVICE_NAME, server_recv_handler, NULL);
    PANIC_IF_FAIL(err, "failed to register second time...\n");

    domainid_t did;
    debug_printf("spawning test binary '%s'\n", TEST_BINARY);
    err = aos_rpc_process_spawn(aos_rpc_get_process_channel(), TEST_BINARY " a", disp_get_core_id(), &did);
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
