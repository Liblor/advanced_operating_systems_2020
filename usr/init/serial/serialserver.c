#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>
#include <rpc/server/ump.h>

#include "serialserver.h"
#include "serial_driver.h"
#include <grading.h>
#include <aos/syscalls.h>
#include <aos/string.h>

static struct rpc_ump_server server;

static struct serialserver_state serial_state;

// --------- urpc marshalling --------------

static errval_t reply_char(
        struct aos_rpc *rpc,
        uint64_t session,
        char c,
        enum rpc_message_status status
)
{
    errval_t err;

    char buf[sizeof(struct rpc_message) + sizeof(struct serial_getchar_reply)];
    struct rpc_message *msg = (struct rpc_message *) &buf;

    msg->cap = NULL_CAP;
    msg->msg.method = Method_Serial_Getchar;
    msg->msg.payload_length = sizeof(struct serial_getchar_reply);
    msg->msg.status = status;
    struct serial_getchar_reply payload = {
            .session = session,
            .data = c
    };
    memcpy(&msg->msg.payload, &payload, sizeof(struct serial_getchar_reply));

    err = aos_rpc_ump_send_message(rpc, msg);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "ump_send_message failed\n");
        return err;
    }

    return SYS_ERR_OK;
}

static void send_getchar_reply(
        struct aos_rpc *rpc
)
{
    errval_t err;

    struct serial_buf_entry *entry = NULL;
    err = cbuf_get(&serial_state.serial_buf, (void **) &entry);
    assert(err_is_ok(err));

    char res_char = entry->val;
    serial_session_t session = serial_state.curr_read_session;
    if (IS_CHAR_LINEBREAK(res_char)) {

        serial_state.curr_read_session = SERIAL_GETCHAR_SESSION_UNDEF;
    }

    err = reply_char(rpc, session, res_char, Status_Ok);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "reply_char() failed");
    }
}

// --------- serial handling --------------

// TODO: replace this with random id to prevent hijacking
static uint64_t new_session(void)
{
    uint64_t s = serial_state.read_session_ctr;
    serial_state.read_session_ctr++;
    return s;
}

__unused
static void
do_getchar_usr(
        struct aos_rpc *rpc,
        struct rpc_message *req,
        struct serial_getchar_req *req_getchar
)
{
    errval_t err;
    if (req_getchar->session == SERIAL_GETCHAR_SESSION_UNDEF) {
        req_getchar->session = new_session();
        SERIAL_SERVER_DEBUG("new serial session: %d\n", req_getchar->session);
    }
    // read is occupied, try again
    if (serial_state.curr_read_session != SERIAL_GETCHAR_SESSION_UNDEF &&
        serial_state.curr_read_session != req_getchar->session) {
        err = reply_char(rpc, req_getchar->session, 0, Serial_Getchar_Occupied);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "reply_char() failed");
        }

        // SERIAL_SERVER_DEBUG("session is occupied: \n");
        return;
    }
    // read is free
    if (serial_state.curr_read_session == SERIAL_GETCHAR_SESSION_UNDEF) {
        serial_state.curr_read_session = req_getchar->session;
        SERIAL_SERVER_DEBUG("request with session %d got serial port\n", req_getchar->session);

        // disable read iqr to prevent race conditions
        dispatcher_handle_t d = disp_disable();
        cbuf_reset(&serial_state.serial_buf);
        disp_enable(d);
    }
    if (cbuf_empty(&serial_state.serial_buf)) {
        // SERIAL_SERVER_DEBUG("deferring request \n");
        serial_state.deferred_rpc = rpc;

        return;
    } else {
        send_getchar_reply(rpc);
    }
}

__unused
static void
do_getchar_sys(
        struct aos_rpc *rpc,
        struct rpc_message *req,
        struct serial_getchar_req *req_getchar
)
{
    errval_t err;
    char c;

    err = sys_getchar(&c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sys_getchar() failed");
    }

    err = reply_char(rpc, req_getchar->session, c, Status_Ok);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "reply_char() failed");
    }
}

__unused
static void do_putchar_sys(
        char c
)
{
    errval_t err;
    err = sys_print((const char *) &c, 1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sys_print() failed");
    }
}

__unused
static void do_putchar_usr(
        char c
)
{
    errval_t err;
    err = serial_driver_write(c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sys_print() failed");
    }
}

__unused
static void do_putstr_usr(
        char *str, size_t len
)
{
    errval_t err;
    err = serial_driver_write_str(str, len);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sys_print() failed");
    }
}

__unused
static void read_irq_cb(
        char c
)
{
    struct serial_buf_entry data = {.val = c};
    cbuf_put(&serial_state.serial_buf, &data);

    if (serial_state.deferred_rpc != NULL) {
        send_getchar_reply(serial_state.deferred_rpc);
        serial_state.deferred_rpc = NULL;
    }
}

// --------- urpc server --------------

static void service_recv_cb(
        struct rpc_message *msg,
        void *callback_state,
        struct aos_rpc *rpc,
        void *server_state
)
{
    char c;
    switch (msg->msg.method) {
        case Method_Serial_Putstr: {
            // TODO: should we forward putstr to grading too?
            {
                char *cptr = (char *) msg->msg.payload;
                for (size_t i = 0; i < msg->msg.payload_length; i++) {
                    grading_rpc_handler_serial_putchar(*(cptr + i));
                }
            }
            // debug_printf("Method_Serial_Putstr: %d: '%s'\n", msg->msg.payload_length, msg->msg.payload);
            do_putstr_usr((char *) msg->msg.payload, msg->msg.payload_length);
            break;
        }
        case Method_Serial_Putchar:
            memcpy(&c, msg->msg.payload, sizeof(char));
            grading_rpc_handler_serial_putchar(c);

#ifdef SERIAL_SERVER_USE_KERNEL
            //            do_putchar_sys(c);
#else
//            do_putchar_usr(c);
#endif
            do_putchar_sys(c);


            break;
        case Method_Serial_Getchar:
            if (msg->msg.payload_length != sizeof(struct serial_getchar_req)) {
                debug_printf("invalid req. for Method_Serial_Getchar");
                return;
            }
            struct serial_getchar_req *req_getchar = (struct serial_getchar_req *) &msg->msg.payload;
            grading_rpc_handler_serial_getchar();

#ifdef SERIAL_SERVER_USE_KERNEL
            do_getchar_sys(rpc, msg, req_getchar);
#else
            do_getchar_usr(rpc, msg, req_getchar);
#endif
            break;
        default:
            debug_printf("unknown method given: %d\n", msg->msg.method);
            break;
    }
}

errval_t serialserver_add_client(
        struct aos_rpc *rpc,
        coreid_t mpid
)
{
    return rpc_ump_server_add_client(&server, rpc);
}

errval_t serialserver_serve_next(void)
{
    return rpc_ump_server_serve_next(&server);
}

errval_t serialserver_init(void)
{
    errval_t err;

    memset(&serial_state, 0, sizeof(struct serialserver_state));
    serial_state.curr_read_session = SERIAL_GETCHAR_SESSION_UNDEF;
    serial_state.read_session_ctr = 0;

    err = cbuf_init(&serial_state.serial_buf,
                    &serial_state.serial_buf_data,
                    sizeof(struct serial_buf_entry),
                    SERIAL_BUF_SLOTS);
    if (err_is_fail(err)) {
        return err;
    }

    err = serial_driver_init();
    if (err_is_fail(err)) {
        debug_printf("error in shell_init(): %s\n", err_getstring(err));
        return err;
    }
    err = serial_driver_set_read_cb(read_irq_cb);
    if (err_is_fail(err)) {
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