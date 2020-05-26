#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"

#include <aos/aos.h>
#include <aos/aos_rpc_ump.h>

#include "serialserver.h"
#include <grading.h>
#include <aos/syscalls.h>
#include <aos/string.h>
#include <aos/nameserver.h>
#include <aos/deferred.h>
#include <arch/aarch64/aos/dispatcher_arch.h>

static struct serialserver_state serial_server;

// Optimization: remove that client need to poll by using nameservice api
// - there are issues with the IQR handler and the driver
// sometimes, iqrs get stuck. Try to poll in periodic event instead

static void release_session(void)
{
    SERIAL_SERVER_DEBUG("releasing session %d\n", serial_server.active->session);
    serial_server.active = NULL;
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
        enum rpc_message_status status)
{
    const size_t size = sizeof(struct rpc_message) + sizeof(struct serial_getchar_reply);
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

inline static errval_t acquire_session(
        struct serial_getchar_req *req,
        struct rpc_message **resp)
{
    errval_t err;

    // acquire session
    serial_server.active = calloc(1, sizeof(struct session_entry));
    serial_server.active->session = req->session;
    err = cbuf_init(&serial_server.active->buf,
                    &serial_server.active->buf_data,
                    sizeof(struct serial_buf_entry),
                    SERIAL_BUF_SLOTS);

    if (err_is_fail(err)) { return err; }

    err = reply_char(resp, req->session, 0, Serial_Getchar_Nodata);
    if (err_is_fail(err)) { goto err_clean_up; }

    // enqueue
    if (serial_server.head == NULL) {
        serial_server.head = serial_server.active;
    } else {
        struct session_entry *next = serial_server.head;
        while (next->next != NULL) {
            next = next->next;
        }
        next->next = serial_server.active;
    }
    return SYS_ERR_OK;

    err_clean_up:
    free(serial_server.active);
    return err;
}

// --------- serial handling --------------
static errval_t do_getchar_usr(
        struct serial_getchar_req *req_getchar,
        struct rpc_message **resp)
{
    errval_t err;
    // give out new session
    if (req_getchar->session == SERIAL_GETCHAR_SESSION_UNDEF) {
        req_getchar->session = new_session();
    }

    struct session_entry *curr = serial_server.head;
    struct session_entry *prev = NULL;

    // we serve already acquired sessions with pending characters
    while (curr != NULL) {
        if (curr->session == req_getchar->session) {
            struct serial_buf_entry *data;
            if (!cbuf_empty(&curr->buf)) {
                err = cbuf_get(&curr->buf, (void **) &data);
                if (err_is_fail(err)) {
                    return err;
                }
                char ret_val = data->val;
                err = reply_char(resp, req_getchar->session, ret_val, Status_Ok);
                if (err_is_fail(err)) {
                    return err;
                }
                if (IS_CHAR_LINEBREAK(ret_val)) {
                    assert(cbuf_empty(&curr->buf));
                    if (prev == NULL) {
                        serial_server.head = curr->next;
                    } else {
                        prev->next = curr->next;
                    }
                    free(curr);
                    curr = NULL;
                }
                return SYS_ERR_OK;
            }
            break;
        }
        prev = curr;
        curr = curr->next;
    }

    if (serial_server.active != NULL) {
        // we own session but dont have characters yet
        if (serial_server.active->session == req_getchar->session) {
            err = reply_char(resp, req_getchar->session, 0, Serial_Getchar_Nodata);
            if (err_is_fail(err)) { return err; }
        } else {
            // someone else owns session
            err = reply_char(resp, req_getchar->session, 0, Serial_Getchar_Occupied);
            if (err_is_fail(err)) { return err; }
        }
    } else {
        // we acquire session
        err = acquire_session(req_getchar, resp);
        if (err_is_fail(err)) { return err; }
    }

    return SYS_ERR_OK;
}

inline static void putchar_kernel(char c)
{
    errval_t err;
    err = sys_print((const char *) &c, 1);
    if (err_is_fail(err)) {
        debug_printf("putchar_kernel failed: %s\n", err_getstring(err));
    }
}

inline static void putchar_usr(char c)
{
    errval_t err;
    err = serial_facade_write(&serial_server.serial_facade, c);
    if (err_is_fail(err)) {
        debug_printf("serial_facade_write failed: %s\n", err_getstring(err));
    }
}

inline static void putstr_usr(const char *str, size_t len)
{
    errval_t err = SYS_ERR_OK;
    for (int i = 0; i < len && err_is_ok(err); i++) {
#if 1
        // XXX: lpuart requires carriage return and line feed
        // In order to be compatible with linux line feed
        // we introduce a carriage return on line break
        if (i > 0
            && *(str + i) == '\n'
            && *(str + i + -1) != '\r') {
            err = serial_facade_write(&serial_server.serial_facade, '\r');
            if (!err_is_ok(err)) {
                break;
            }
        }
#endif
        err = serial_facade_write(&serial_server.serial_facade, *(str + i));
    }
    if (err_is_fail(err)) {
        debug_printf("serial_facade_write failed: %s\n", err_getstring(err));
    }
}


static void getchar_iqr_handler(char c, void *args)
{
    if (serial_server.active != NULL) {
        struct serial_buf_entry data = {
                .val = c
        };
        cbuf_put(&serial_server.active->buf, &data);

        if (IS_CHAR_LINEBREAK(c)) {
            release_session();
        }
    }
#if 0
    serial_facade_write(&serial_server.serial_facade, c);
#endif
}

// --------- urpc server --------------

inline static void service_recv_handle_putstr(struct rpc_message *msg)
{
    char *cptr = (char *) msg->msg.payload;
    for (size_t i = 0; i < msg->msg.payload_length; i++) {
        grading_rpc_handler_serial_putchar(*(cptr + i));
    }

    // XXX: Hacky workaround
    // the UMP library seems to cause troubles
    // when transfering content across cores
    // we only get gibberish in payload
    // if we are too quick
    struct dispatcher_generic *disp = get_dispatcher_generic(curdispatcher());
    barrelfish_usleep(30);
    putstr_usr(msg->msg.payload, msg->msg.payload_length);
}

inline static void service_recv_handle_putchar(struct rpc_message *msg)
{
    char c;
    memcpy(&c, msg->msg.payload, sizeof(char));
    grading_rpc_handler_serial_putchar(c);
    putchar_usr(c);
}

inline static void service_recv_handle_getchar(struct rpc_message *msg, struct rpc_message **resp)
{
    grading_rpc_handler_serial_getchar();

    if (msg->msg.payload_length != sizeof(struct serial_getchar_req)) {
        debug_printf("invalid req. for Method_Serial_Getchar");
        return;
    }
    struct serial_getchar_req req_getchar;
    memcpy(&req_getchar, msg->msg.payload, sizeof(struct serial_getchar_req));
    errval_t err = do_getchar_usr(&req_getchar, resp);
    if (err_is_fail(err)) {
        debug_printf("failure in do_getchar_usr: %s\n", err_getstring(err));
    }
}

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
}

static errval_t serialserver_init(void)
{
    errval_t err;
    memset(&serial_server, 0, sizeof(struct serialserver_state));
    serial_server.read_session_ctr = 0;
    serial_server.head = NULL;
    serial_server.active = NULL;

    err = serial_facade_init(&serial_server.serial_facade, SERIAL_FACADE_TARGET_CPU_0, false);
    if (err_is_fail(err)) {
        debug_printf("error in shell_init(): %s\n", err_getstring(err));
        return err;
    }
    err = serial_facade_set_read_cb(&serial_server.serial_facade,
                                    getchar_iqr_handler,
                                    NULL);
    if (err_is_fail(err)) {
        debug_printf("failed to call serial_facade_set_read_cb() %s\n", err_getstring(err));
        return err;
    }
    return SYS_ERR_OK;
}

static void poll_read(void *args)
{
    char c;
    errval_t err = serial_facade_poll_read(&serial_server.serial_facade, &c);
    if (err_is_ok(err)) {
        if (serial_server.active != NULL) {
            struct serial_buf_entry data = {
                    .val = c
            };
            cbuf_put(&serial_server.active->buf, &data);
            if (IS_CHAR_LINEBREAK(c)) {
                release_session();
            }
        }
    }
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
    struct periodic_event periodic_urpc_ev;
    err = periodic_event_create(&periodic_urpc_ev,
                                get_default_waitset(),
                                100,
                                MKCLOSURE(poll_read, NULL));

    if (err_is_fail(err)){
        debug_printf("%s\n", err_getstring(err));
        abort();
    }

    debug_printf("Serialserver registered at nameserver.\n");
    while (1) {
        // XXX: we need to call event_dispatch otherwise
        // iqr are not delivered
        err = event_dispatch(get_default_waitset());
        if (err != LIB_ERR_NO_EVENT && err_is_fail(err)) {
            debug_printf("error occured in serialserver: %s\n", err_getstring(err));
        }
        thread_yield();
    }
    return EXIT_SUCCESS;
}
