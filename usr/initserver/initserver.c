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

    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }
}
