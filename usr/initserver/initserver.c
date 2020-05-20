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
#include <aos/aos_rpc.h>
#include <aos/nameserver.h>
#include <grading.h>

static void handle_number(uintptr_t num)
{
    grading_rpc_handle_number(num);
#if 1
    debug_printf("handle_number(%llu)\n", num);
#endif
}

static void handle_string(char *c)
{
    grading_rpc_handler_string(c);
#if 1
    debug_printf("handle_string(%s)\n", c);
#endif
}

static void service_handler(void *st, void *message, size_t bytes, void **response, size_t *response_bytes, struct capref tx_cap, struct capref *rx_cap)
{
    struct rpc_message *msg = message;

    uintptr_t num;
    size_t last_idx;

	switch (msg->msg.method) {
    case Method_Send_Number:
        memcpy(&num, msg->msg.payload, sizeof(uint64_t));

        handle_number(num);
        break;
    case Method_Send_String:
        // Make sure that the string is null-terminated
        last_idx = msg->msg.payload_length - 1;
        msg->msg.payload[last_idx] = '\0';

        handle_string(msg->msg.payload);
        break;
    default:
        debug_printf("Received unknown method.\n");
        break;
	}
}

int main(int argc, char *argv[])
{
    errval_t err;

    debug_printf("Initserver spawned.\n");

    err = nameservice_register(NAMESERVICE_INIT, service_handler, NULL);
    if (err_is_fail(err)) {
        debug_printf("nameservice_register() failed: %s\n", err_getstring(err));
        abort();
    }

    debug_printf("Initserver registered at nameserver.\n");
    while (true) {
        thread_yield();
    }
}
