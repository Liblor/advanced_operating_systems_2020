#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>
#include <rpc/server/ump.h>

#include "serialserver.h"
#include "serial_driver.h"
#include <grading.h>

static struct rpc_ump_server server;

// ring buffer to store read data
static struct serial_read_data read_data;

static void putchar_sys(char c);
static void getchar_sys(char *c);
static void putchar_usr(char c);
//static void getchar_usr(char *c);

static errval_t reply_char(
        struct aos_rpc *rpc,
        char c
){

    errval_t err;

    char buf[sizeof(struct rpc_message) + sizeof(char)];
    struct rpc_message *msg = (struct rpc_message*) &buf;

    msg->cap = NULL_CAP;
    msg->msg.method = Method_Serial_Getchar;
    msg->msg.payload_length = sizeof(c);
    msg->msg.status = Status_Ok;
    msg->msg.payload[0] = c;

    err = aos_rpc_ump_send_message(rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "ump_send_message failed\n");
        return err;
    }

    return SYS_ERR_OK;
}

static void service_recv_cb(
        struct rpc_message *msg,
        void *callback_state,
        struct aos_rpc *rpc,
        void *server_state)
{
    errval_t err;
    char c;
    switch (msg->msg.method) {
    case Method_Serial_Putchar:
        memcpy(&c, msg->msg.payload, sizeof(char));
            // TODO: Macro
            // putchar_sys(c);
            putchar_usr(c);
        break;
    case Method_Serial_Getchar:
        // TODO Currently, if this callback blocks (which is does if
        // the callback calls sys_getchar) the server cannot process
        // other requests. This could be solved by giving this callback
        // another callback to send the response, so that the server
        // doesn't have to wait for this callback to complete.
        getchar_sys(&c);
        err = reply_char(rpc, c);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "reply_char() failed");
        }
        break;
    default:
        break;
    }
}

errval_t serialserver_add_client(struct aos_rpc *rpc, coreid_t mpid)
{
    return rpc_ump_server_add_client(&server, rpc);
}

errval_t serialserver_serve_next(void)
{
    return rpc_ump_server_serve_next(&server);
}

__unused
static void putchar_sys(char c) {
    errval_t err;

    grading_rpc_handler_serial_putchar(c);

    err = sys_print((const char *)&c, 1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sys_print() failed");
    }
}

__unused
static void getchar_sys(char *c) {
    errval_t err;

    grading_rpc_handler_serial_getchar();

    err = sys_getchar(c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sys_getchar() failed");
    }
}

__unused
static void putchar_usr(char c) {
    errval_t err;

    grading_rpc_handler_serial_putchar(c);

    err = serial_driver_write(c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sys_print() failed");
    }
}

__unused
static bool read_data_empty(void)
{
    return read_data.head == read_data.tail;
}

__unused
static void read_data_advance(void)
{
    if (read_data.full)
    {
        read_data.tail = (read_data.tail + 1) % READ_DATA_SLOTS;
//        debug_printf("read buffer is full\n");
    }
    read_data.head = (read_data.head + 1) % READ_DATA_SLOTS;
    read_data.full = read_data.head == read_data.tail;
}

__unused
static void read_data_retreat(void)
{
    read_data.tail = (read_data.tail + 1) % READ_DATA_SLOTS;
    read_data.full = false;
}

__unused
static void read_data_put(struct serial_read_slot data)
{
    read_data.data[read_data.head] = data;
    read_data_advance();
}

__unused
static errval_t read_data_get(struct serial_read_slot **ret_data)
{
    if (read_data_empty()) {
        return LIB_ERR_NOT_IMPLEMENTED;
    }
    *ret_data = &read_data.data[read_data.tail];
    read_data_retreat();
    return SYS_ERR_OK;
}

__unused
static void read_irq_cb(char c)
{
    struct serial_read_slot data = { .val = c };
    read_data_put(data);
}

errval_t serialserver_init(void)
{
    errval_t err;
    err = serial_driver_init();
    if(err_is_fail(err)){
        debug_printf("error in shell_init(): %s\n", err_getstring(err));
        return err;
    }

    memset(&read_data, 0, sizeof(read_data));

    err = serial_driver_set_read_cb(read_irq_cb);
    if(err_is_fail(err)){
        return err;
    }

    err = rpc_ump_server_init(&server,
            service_recv_cb,
            NULL,
            NULL,
            NULL);

    if (err_is_fail(err)) {
        debug_printf("rpc_ump_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}