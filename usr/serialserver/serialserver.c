#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>

#include "serialserver.h"
#include <grading.h>
#include <aos/syscalls.h>
#include <aos/string.h>
#include <aos/nameserver.h>
#include <aos/deferred.h>

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

// ---------  marshalling --------------

static errval_t reply_char(
        struct rpc_message **resp,
        uint64_t session,
        char c,
        enum rpc_message_status status
)
{
    const size_t size = sizeof(struct rpc_message)
                        + sizeof(struct serial_getchar_reply);
    struct rpc_message *msg = calloc(1, size);
    if (msg == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->cap = NULL_CAP;
    msg->msg.method = Method_Serial_Getchar;
    msg->msg.payload_length = sizeof(struct serial_getchar_reply);
    msg->msg.status = status;
    struct serial_getchar_reply payload = {
            .session = session,
            .data = c
    };
    memcpy(&msg->msg.payload, &payload, sizeof(struct serial_getchar_reply));
    *resp = msg;
    return SYS_ERR_OK;
}

static void send_getchar_reply(
        struct rpc_message **resp
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

    err = reply_char(resp, session, res_char, Status_Ok);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "reply_char() failed");
    }
}

// --------- serial handling --------------

__unused
static void
do_getchar_usr(
        struct serial_getchar_req *req_getchar,
        struct rpc_message **resp
)
{
    errval_t err;
    if (req_getchar->session == SERIAL_GETCHAR_SESSION_UNDEF) {
        req_getchar->session = new_session();
    }

    // read is occupied, try again
    if (serial_server.curr_read_session != SERIAL_GETCHAR_SESSION_UNDEF &&
        serial_server.curr_read_session != req_getchar->session) {
        err = reply_char(resp, req_getchar->session, 0, Serial_Getchar_Occupied);
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
        err = reply_char(resp, req_getchar->session, 0, Serial_Getchar_Nodata);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "reply_char() failed");
        }

        // TODO optimization get rid of polling
        // SERIAL_SERVER_DEBUG("deferring request \n");
//        serial_server.deferred_rpc = rpc;
        return;
    } else {
        send_getchar_reply(resp);
    }
}

__unused static void do_putchar_sys(
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
static void getchar_iqr_handler(
        char c,
        void *args

)
{
    struct serial_buf_entry data = {.val = c};
    cbuf_put(&serial_server.serial_buf, &data);

#if 0
    serial_facade_write(&serial_server.serial_facade, c);
#endif

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
        struct rpc_message *msg)
{
    char *cptr = (char *) msg->msg.payload;
    for (size_t i = 0; i < msg->msg.payload_length; i++) {
        grading_rpc_handler_serial_putchar(*(cptr + i));
    }
    do_putstr_usr((char *) msg->msg.payload, msg->msg.payload_length);
}

__inline
static void service_recv_handle_putchar(
        struct rpc_message *msg)
{
    char c;
    memcpy(&c, msg->msg.payload, sizeof(char));
    grading_rpc_handler_serial_putchar(c);

    do_putchar_usr(c);
}

__inline
static void service_recv_handle_getchar(
        struct rpc_message *msg,
        struct rpc_message **resp
)
{
    grading_rpc_handler_serial_getchar();

    if (msg->msg.payload_length != sizeof(struct serial_getchar_req)) {
        debug_printf("invalid req. for Method_Serial_Getchar");
        return;
    }

    struct serial_getchar_req req_getchar;
    memcpy(&req_getchar, msg->msg.payload, sizeof(struct serial_getchar_req));

    do_getchar_usr(&req_getchar, resp);
}

__unused
static void ns_service_handler(
        void *st,
        void *message,
        size_t bytes,
        void **response,
        size_t *response_bytes,
        struct capref tx_cap,
        struct capref *rx_cap)
{

    struct rpc_message *msg = message;
    struct rpc_message *resp_msg = NULL;
    switch (msg->msg.method) {
        case Method_Serial_Putchar:
            service_recv_handle_putchar(msg);
            break;
        case Method_Serial_Putstr:
            service_recv_handle_putstr(msg);
            break;
        case Method_Serial_Getchar:
            service_recv_handle_getchar(msg, &resp_msg);
            break;
        default:
            debug_printf("unknown method given: %d\n", msg->msg.method);
            break;
    }

    if (resp_msg == NULL) {
        *response = NULL;
        *response_bytes = 0;
    } else {
        *response = resp_msg;
        *response_bytes = sizeof(struct rpc_message) + resp_msg->msg.payload_length;
    }
    return;
}

__unused
static errval_t serialserver_init(void)
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
        debug_printf("failed to init cbuf_init(): %s\n",
                     err_getstring(err));
        return err;
    }

    err = serial_facade_init(&serial_server.serial_facade,
                             SERIAL_FACADE_TARGET_CPU_0);
    if (err_is_fail(err)) {
        debug_printf("error in shell_init(): %s\n",
                     err_getstring(err));
        return err;
    }

    err = serial_facade_set_read_cb(&serial_server.serial_facade,
                                    getchar_iqr_handler,
                                    NULL);
    if (err_is_fail(err)) {
        debug_printf("failed to call serial_facade_set_read_cb() %s\n",
                     err_getstring(err));
        return err;
    }

    return SYS_ERR_OK;
}

int main(int argc, char *argv[])
{
    errval_t err = SYS_ERR_OK;

    err = serialserver_init();
    if (err_is_fail(err)) {
        debug_printf("failed to init features of serial server: %s\n", err_getstring(err));
        abort();
    }
    err = nameservice_register(NAMESERVICE_SERIAL,
                               ns_service_handler,
                               NULL);
    if (err_is_fail(err)) {
        debug_printf("nameservice_register() failed: %s\n", err_getstring(err));
        abort();
    }
    debug_printf("Serialserver registered at nameserver.\n");

    while (1) {
        // XXX: we need to call event_dispatch otherwise
        // iqr are not delivered

        err = event_dispatch_non_block(get_default_waitset());
        if (err != LIB_ERR_NO_EVENT && err_is_fail(err)) {
            debug_printf("error occured in serialserver: %s\n", err_getstring(err));
        }
        thread_yield();
    }
    return EXIT_SUCCESS;
}