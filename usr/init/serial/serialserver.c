#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>

#include "serialserver.h"
#include <grading.h>
#include <aos/syscalls.h>
#include <aos/string.h>

static struct serialserver_state serial_server;

static void release_session(void)
{
    SERIAL_SERVER_DEBUG("releasing session %d\n", serial_server.curr_read_session);
    serial_server.curr_read_session = SERIAL_GETCHAR_SESSION_UNDEF;
}

// TODO: replace this with random id to prevent hijacking
static uint64_t new_session(void)
{
    uint64_t s = serial_server.read_session_ctr;
    SERIAL_SERVER_DEBUG("new serial session: %d\n", s);
    serial_server.read_session_ctr++;
    return s;
}

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
    err = cbuf_get(&serial_server.serial_buf, (void **) &entry);
    assert(err_is_ok(err));

    char res_char = entry->val;
    serial_session_t session = serial_server.curr_read_session;

    if (IS_CHAR_LINEBREAK(res_char)) {
        release_session();
    }

    err = reply_char(rpc, session, res_char, Status_Ok);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "reply_char() failed");
    }
}

// --------- serial handling --------------

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
        debug_printf("new serial session\n");
    }
    // read is occupied, try again
    if (serial_server.curr_read_session != SERIAL_GETCHAR_SESSION_UNDEF &&
        serial_server.curr_read_session != req_getchar->session) {
        err = reply_char(rpc, req_getchar->session, 0, Serial_Getchar_Occupied);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "reply_char() failed");
        }
         SERIAL_SERVER_DEBUG("session is occupied: \n");
        return;
    }

    // read is free
    if (serial_server.curr_read_session == SERIAL_GETCHAR_SESSION_UNDEF) {
        serial_server.curr_read_session = req_getchar->session;
        SERIAL_SERVER_DEBUG("session %d acquired serial port\n", req_getchar->session);

        // disable read iqr to prevent race conditions
        dispatcher_handle_t d = disp_disable();
        cbuf_reset(&serial_server.serial_buf);
        disp_enable(d);
    }
    if (cbuf_empty(&serial_server.serial_buf)) {
        // SERIAL_SERVER_DEBUG("session %d no data\n", req_getchar->session);
        err = reply_char(rpc, req_getchar->session, 0, Serial_Getchar_Nodata);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "reply_char() failed");
        }

        // TODO optimization get rid of polling
        // SERIAL_SERVER_DEBUG("deferring request \n");
//        serial_server.deferred_rpc = rpc;
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
    err = serial_facade_write(&serial_server.serial_facade, c);
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
    err = serial_facade_write_str(&serial_server.serial_facade, str, len);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sys_print() failed");
    }
}

__unused
static void read_irq_cb(
        char c,
        void *args

)
{
    struct serial_buf_entry data = {.val = c};
    cbuf_put(&serial_server.serial_buf, &data);

    // TODO: in case monitor is not a serializer for rpc requests
    // reply only on new data such that client dont need to poll
#if 0
    if (serial_server.deferred_rpc != NULL) {
        // reply and release session if newline arrives
        send_getchar_reply(serial_server.deferred_rpc);
        serial_server.deferred_rpc = NULL;
    } else {
        // we serve chars on a line basis so a newline
        // frees a locked session
        if (IS_CHAR_LINEBREAK(c)) {
            release_session();
        }
    }
#endif
}

// --------- urpc server --------------

__inline
static void service_recv_handle_putstr(
        struct rpc_message *msg,
        void *callback_state,
        struct aos_rpc *rpc,
        void *server_state
)
{
    char *cptr = (char *) msg->msg.payload;
    for (size_t i = 0; i < msg->msg.payload_length; i++) {
        grading_rpc_handler_serial_putchar(*(cptr + i));
    }

    do_putstr_usr((char *) msg->msg.payload, msg->msg.payload_length);
}

__inline
static void service_recv_handle_putchar(
        struct rpc_message *msg,
        void *callback_state,
        struct aos_rpc *rpc,
        void *server_state
)
{
    char c;
    memcpy(&c, msg->msg.payload, sizeof(char));
    grading_rpc_handler_serial_putchar(c);

//     do_putchar_sys(c); // kernel impl
    do_putchar_usr(c);    // userspace impl
}

__inline
static void service_recv_handle_getchar(
        struct rpc_message *msg,
        void *callback_state,
        struct aos_rpc *rpc,
        void *server_state
)
{
    grading_rpc_handler_serial_getchar();

    if (msg->msg.payload_length != sizeof(struct serial_getchar_req)) {
        debug_printf("invalid req. for Method_Serial_Getchar");
        return;
    }
    struct serial_getchar_req req_getchar;
    memcpy(&req_getchar, msg->msg.payload, sizeof(struct serial_getchar_req));

//     do_getchar_sys(rpc, msg, &req_getchar);  // kernel impl
    do_getchar_usr(rpc, msg, &req_getchar);     // user space impl
}

static void service_recv_cb(
        struct rpc_message *msg,
        void *callback_state,
        struct aos_rpc *rpc,
        void *server_state
)
{
    switch (msg->msg.method) {
        case Method_Serial_Putstr: {
            service_recv_handle_putstr(msg, callback_state, rpc, server_state);
            break;
        }
        case Method_Serial_Putchar:
            service_recv_handle_putchar(msg, callback_state, rpc, server_state);
            break;
        case Method_Serial_Getchar:
            service_recv_handle_getchar(msg, callback_state, rpc, server_state);
            break;
        default:
            debug_printf("unknown method given: %d\n", msg->msg.method);
            break;
    }
}

errval_t serialserver_add_client(
        struct aos_rpc *rpc,
        coreid_t mpid)
{
    return rpc_ump_server_add_client(&serial_server.ump_server, rpc);
}

errval_t serialserver_serve_next(void)
{
    return rpc_ump_server_serve_next(&serial_server.ump_server);
}

errval_t serialserver_init(void)
{
    errval_t err;

    memset(&serial_server, 0, sizeof(struct serialserver_state));
    serial_server.curr_read_session = SERIAL_GETCHAR_SESSION_UNDEF;
    serial_server.read_session_ctr = 0;

    err = cbuf_init(&serial_server.serial_buf,
                    &serial_server.serial_buf_data,
                    sizeof(struct serial_buf_entry),
                    SERIAL_BUF_SLOTS);

    if (err_is_fail(err)) {
        debug_printf("failed to init cbuf_init(): %s\n", err_getstring(err));
        return err;
    }

    err = serial_facade_init(&serial_server.serial_facade,
                             SERIAL_FACADE_TARGET_CPU_0);
    if (err_is_fail(err)) {
        debug_printf("error in shell_init(): %s\n", err_getstring(err));
        return err;
    }

    err = serial_facade_set_read_cb(&serial_server.serial_facade,
                                    read_irq_cb,
                                    NULL);
    if (err_is_fail(err)) {
        debug_printf("failed to call serial_facade_set_read_cb() %s\n", err_getstring(err));
        return err;
    }

    err = rpc_ump_server_init(&serial_server.ump_server,
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