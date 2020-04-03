#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/aos_rpc_lmp_marshal.h>

static struct aos_rpc *init_channel = NULL;
static struct aos_rpc *memory_channel = NULL;
static struct aos_rpc *process_channel = NULL;
static struct aos_rpc *serial_channel = NULL;

/** common header validations for receive payloads */
static inline errval_t
validate_recv_header(struct lmp_recv_msg *msg, enum pending_state state,
                     enum rpc_message_method method)
{
    if (state == EmptyState) {
        return_err(msg == NULL, "msg is null");
        return_err(sizeof(uint64_t) * msg->buf.buflen < sizeof(struct rpc_message_part),
                   "invalid buflen");
        const struct rpc_message_part *msg_part = (struct rpc_message_part *) msg->words;
        return_err(msg_part->status != Status_Ok, "status not ok");
        return_err(msg_part->method != method, "wrong method in response");
    }
    return SYS_ERR_OK;
}

void
aos_rpc_lmp_handler_print(char *string, uintptr_t *val, struct capref *cap)
{
    if (string) {
        debug_printf("||TEST %s length %zu \n", string, strlen(string));
    }
    if (val) {
        debug_printf("||TEST %d \n", *val);
    }
    if (cap && !capref_is_null(*cap)) {
        char buf[256];
        debug_print_cap_at_capref(buf, 256, *cap);
        debug_printf("||TEST %s \n", buf);
    }
}

errval_t
aos_rpc_lmp_init(struct aos_rpc *rpc)
{
    lmp_chan_init(&rpc->lc);

    struct aos_rpc_lmp *rpc_lmp = malloc(sizeof(struct aos_rpc_lmp));
    if (rpc_lmp == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    memset(rpc_lmp, 0, sizeof(struct aos_rpc_lmp));
    rpc->lmp = rpc_lmp;

    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    uint8_t send_buf[sizeof(struct rpc_message) + sizeof(num)];

    struct rpc_message *msg = (struct rpc_message *) &send_buf;
    msg->msg.method = Method_Send_Number;
    msg->msg.payload_length = sizeof(num);
    msg->msg.status = Status_Ok;
    msg->cap = NULL_CAP;
    memcpy(msg->msg.payload, &num, sizeof(num));

    return aos_rpc_lmp_send_message(&rpc->lc, msg, LMP_SEND_FLAGS_DEFAULT);
}


errval_t
aos_rpc_lmp_send_string(struct aos_rpc *rpc, const char *string)
{
    const uint32_t str_len = MIN(strnlen(string, RPC_LMP_MAX_STR_LEN) + 1,
                                 RPC_LMP_MAX_STR_LEN);  //  strln \0 not included

    uint8_t send_buf[sizeof(struct rpc_message) + str_len];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->msg.method = Method_Send_String;
    msg->msg.payload_length = str_len;
    msg->cap = NULL_CAP;
    msg->msg.status = Status_Ok;
    strlcpy(msg->msg.payload, string, str_len);

    return aos_rpc_lmp_send_message(&rpc->lc, msg, LMP_SEND_FLAGS_DEFAULT);
}

static errval_t
validate_get_ram_cap(struct lmp_recv_msg *msg, enum pending_state state)
{
    errval_t err = validate_recv_header(msg, state, Method_Get_Ram_Cap);
    if (err_is_fail(err)) {
        return err;
    }
    if (state == EmptyState) {
        const struct rpc_message_part *msg_part = (struct rpc_message_part *) msg->words;
        return_err(msg_part->payload_length != sizeof(size_t),
                   "no return size in payload");
    }
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                        struct capref *ret_cap, size_t *ret_bytes)
{
    errval_t err;

    const size_t payload_length = sizeof(bytes) + sizeof(alignment);
    uint8_t send_buf[sizeof(struct rpc_message) + payload_length];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->msg.method = Method_Get_Ram_Cap;
    msg->msg.payload_length = payload_length;
    msg->msg.status = Status_Ok;
    msg->cap = NULL_CAP;
    memcpy(msg->msg.payload, &bytes, sizeof(bytes));
    memcpy(msg->msg.payload + sizeof(bytes), &alignment, sizeof(alignment));

    struct rpc_message *recv = NULL;
    err = aos_rpc_lmp_send_and_wait_recv(rpc, msg, &recv, validate_get_ram_cap);
    if (err_is_fail(err)) {
        goto clean_up;
    }
    if (capref_is_null(recv->cap)) {
        err = LIB_ERR_LMP_INVALID_RESPONSE;
        goto clean_up;
    }
    *ret_cap = recv->cap;

    if (ret_bytes != NULL) {
        /* TODO:
         * Compiler Alignment Undef Behaviour
         * char payload[0] may lead to alignment issues when
         * payload is copied by assign, not by memcopy
         *
         * This Fails:
         * *ret_bytes = * ((size_t *) recv->msg.payload);
         *
         * This Works:
         * memcpy(ret_bytes, recv->msg.payload, sizeof(size_t));
         */
        memcpy(ret_bytes, recv->msg.payload, sizeof(size_t));
    }

    err = SYS_ERR_OK;
    goto clean_up;

    clean_up:
    if (recv != NULL) {
        free(recv);
    }
    return err;
}

static errval_t
validate_serial_getchar(struct lmp_recv_msg *msg, enum pending_state state)
{
    return validate_recv_header(msg, state, Method_Serial_Getchar);
}

errval_t
aos_rpc_lmp_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    errval_t err;
    uint8_t send_buf[sizeof(struct rpc_message)];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->cap = NULL_CAP;
    msg->msg.method = Method_Serial_Getchar;
    msg->msg.payload_length = 0;
    msg->msg.status = Status_Ok;

    struct rpc_message *recv = NULL;
    err = aos_rpc_lmp_send_and_wait_recv(rpc, msg, &recv, validate_serial_getchar);
    if (err_is_fail(err)) {
        return err;
    }

    // always use memcpy when dealing with payload[0] (alignment issues)
    memcpy(retc, recv->msg.payload, sizeof(char));
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_serial_putchar(struct aos_rpc *rpc, char c)
{
    uint8_t send_buf[sizeof(struct rpc_message) + sizeof(char)];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->cap = NULL_CAP;
    msg->msg.method = Method_Serial_Putchar;
    msg->msg.payload_length = sizeof(char);
    msg->msg.status = Status_Ok;
    memcpy(msg->msg.payload, &c, sizeof(char));

    errval_t err = aos_rpc_lmp_send_message(&rpc->lc, msg, LMP_SEND_FLAGS_DEFAULT);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_send_message failed\n");
        return err;
    }
    return SYS_ERR_OK;
}

static errval_t
validate_process_spawn(struct lmp_recv_msg *msg, enum pending_state state)
{
    errval_t err = validate_recv_header(msg, state, Method_Spawn_Process);
    if (err_is_fail(err)) {
        return err;
    }
    if (state == EmptyState) {
        const struct rpc_message_part *msg_part = (struct rpc_message_part *) msg->words;
        return_err(msg_part->payload_length != sizeof(size_t) + sizeof(domainid_t),
                   "invalid payload len");
    }
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_process_spawn(struct aos_rpc *rpc, char *cmdline,
                          coreid_t core, domainid_t *newpid)
{
    errval_t err;
    const uint32_t str_len =
            MIN(strnlen(cmdline, RPC_LMP_MAX_STR_LEN) + 1, RPC_LMP_MAX_STR_LEN); // no \0 in strlen
    const size_t payload_len = str_len + sizeof(core);

    uint8_t send_buf[sizeof(struct rpc_message) + payload_len];
    struct rpc_message *send = (struct rpc_message *) &send_buf;

    send->msg.method = Method_Spawn_Process;
    send->msg.payload_length = sizeof(core) + str_len;
    send->cap = NULL_CAP;
    send->msg.status = Status_Ok;
    memcpy(send->msg.payload, &core, sizeof(core));
    strlcpy(send->msg.payload + sizeof(core), cmdline, str_len);

    struct rpc_message *recv = NULL;
    err = aos_rpc_lmp_send_and_wait_recv(rpc, send, &recv, validate_process_spawn);
    if (err_is_fail(err)) {
        goto clean_up;
    }

    struct process_pid_array *pid_array = (struct process_pid_array *) &recv->msg.payload;
    *newpid = pid_array->pids[0];

    assert(pid_array->pid_count == 1);
    err = SYS_ERR_OK;
    goto clean_up;

clean_up:
    free(recv);
    return err;
}

static errval_t
validate_process_get_name(struct lmp_recv_msg *msg, enum pending_state state)
{
    return validate_recv_header(msg, state, Method_Process_Get_Name);
}

errval_t
aos_rpc_lmp_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name) {
    errval_t err;
    const size_t payload_len = sizeof(pid);
    uint8_t send_buf[sizeof(struct rpc_message) + payload_len];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->cap = NULL_CAP;
    msg->msg.method = Method_Process_Get_Name;
    msg->msg.payload_length = payload_len;
    msg->msg.status = Status_Ok;
    memcpy(msg->msg.payload, &pid, sizeof(pid));

    struct rpc_message *recv = NULL;
    err = aos_rpc_lmp_send_and_wait_recv(rpc, msg, &recv, validate_process_get_name);
    if (err_is_fail(err)) {
        goto clean_up_recv;
    }

    *name = malloc(recv->msg.payload_length);
    if (*name == NULL) {
        err = LIB_ERR_MALLOC_FAIL;
        goto clean_up_recv;
    }

    strlcpy(*name, recv->msg.payload, recv->msg.payload_length);
    err = SYS_ERR_OK;
    goto clean_up_recv;

    clean_up_recv:
    if (recv != NULL) {
        free(recv);
    }
    return err;
}

static errval_t
validate_process_get_all_pids(struct lmp_recv_msg *msg, enum pending_state state)
{
    return validate_recv_header(msg, state, Method_Process_Get_All_Pids);
}

errval_t
aos_rpc_lmp_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                 size_t *pid_count)
{
    errval_t err;
    uint8_t send_buf[sizeof(struct rpc_message)];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->cap = NULL_CAP;
    msg->msg.method = Method_Process_Get_All_Pids;
    msg->msg.payload_length = 0;
    msg->msg.status = Status_Ok;

    struct rpc_message *recv = NULL;
    err = aos_rpc_lmp_send_and_wait_recv(rpc, msg, &recv, validate_process_get_all_pids);
    if (err_is_fail(err)) {
        goto clean_up;
    }
    struct process_pid_array *pid_array = (struct process_pid_array *) &recv->msg.payload;
    assert(pid_array != NULL);

    *pid_count = pid_array->pid_count;

    const size_t total_length = *pid_count * sizeof(domainid_t);
    *pids = malloc(total_length);
    if (*pids == NULL) {
        goto clean_up;
    }

    memcpy(*pids, pid_array->pids, total_length);
    err = SYS_ERR_OK;
    goto clean_up;

    clean_up:
    if (recv != NULL) {
        free(recv);
    }
    return err;
}

errval_t
aos_rpc_lmp_get_device_cap(struct aos_rpc *rpc, lpaddr_t paddr, size_t bytes,
                           struct capref *ret_cap)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

static void
client_recv_open_cb(void *args)
{
    errval_t err;

    struct aos_rpc *rpc = (struct aos_rpc *) args;
    struct lmp_chan *lc = &rpc->lc;

    struct capref server_cap;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    err = lmp_chan_recv(lc, &msg, &server_cap);
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_recv() failed: %s\n", err_getstring(err));
        return;
    }

    // In case no capability was sent, return.
    if (capref_is_null(server_cap)) {
        debug_printf("open_recv_cb() could not retrieve a capability.");
        return;
    }

    lc->remote_cap = server_cap;
}

static struct aos_rpc *
aos_rpc_lmp_setup_channel(struct capref remote_cap, const char *service_name)
{
    errval_t err;
    struct aos_rpc *rpc = malloc(sizeof(struct aos_rpc));
    if (rpc == NULL) {
        debug_printf("malloc returned NULL\n");
        return NULL;
    }
    err = aos_rpc_lmp_init(rpc);
    if (err_is_fail(err)) {
        debug_printf("error in %s\n", service_name);
        DEBUG_ERR(err, "error in aos_rpc_lmp_init");
        return NULL;
    }

    struct lmp_chan *lc = &rpc->lc;

    struct capref cap_ep;
    err = endpoint_create(DEFAULT_LMP_BUF_WORDS, &cap_ep, &lc->endpoint);
    if (err_is_fail(err)) {
        debug_printf("error in %s\n", service_name);
        debug_printf("endpoint_create() failed: %s\n", err_getstring(err));
        return NULL;
    }

    lc->local_cap = cap_ep;
    lc->remote_cap = remote_cap;

    struct waitset ws;
    waitset_init(&ws);

    // The closure will be removed from the waitset after it has been executed
    // once. We don't use the default waitset, because we want to be able to
    // wait on a specific response below.
    err = lmp_chan_register_recv(lc, &ws, MKCLOSURE(client_recv_open_cb, rpc));
    if (err_is_fail(err)) {
        debug_printf("error in %s\n", service_name);
        debug_printf("lmp_chan_register_recv() failed: %s\n", err_getstring(err));
        return NULL;
    }

    // Allocate receive slot to receive the capability of the service endpoint
    err = lmp_chan_alloc_recv_slot(lc);
    if (err_is_fail(err)) {
        debug_printf("error in %s\n", service_name);
        debug_printf("lmp_chan_alloc_recv_slot() failed: %s\n", err_getstring(err));
        return NULL;
    }

    do {
        err = lmp_chan_send0(lc, LMP_SEND_FLAGS_DEFAULT, cap_ep);
        if (lmp_err_is_transient(err)) {
            DEBUG_ERR(err, "transient");
        }
    } while (lmp_err_is_transient(err));
    if (err_is_fail(err)) {
        debug_printf("error in %s\n", service_name);
        debug_printf("lmp_chan_send0() failed: %s\n", err_getstring(err));
        return NULL;
    }

    // Wait for the callback to be executed.
    err = event_dispatch(&ws);
    if (err_is_fail(err)) {
        debug_printf("error in %s\n", service_name);
        debug_printf("event_dispatch() failed: %s\n", err_getstring(err));
        return NULL;
    }

    err = waitset_destroy(&ws);
    if (err_is_fail(err)) {
        debug_printf("error in %s\n", service_name);
        debug_printf("waitset_destroy() failed: %s\n", err_getstring(err));
        // We don't have to return NULL, this error is not critical.
    }

    return rpc;
}

/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *
aos_rpc_lmp_get_init_channel(void)
{
    if (init_channel == NULL) {
        init_channel = aos_rpc_lmp_setup_channel(cap_chan_init, "init");
        if (init_channel == NULL) {
            debug_printf("aos_rpc_lmp_setup_channel() failed\n");
            return NULL;
        }
    }

    return init_channel;
}

/**
 * \brief Returns the channel to the memory server.
 */
struct aos_rpc *
aos_rpc_lmp_get_memory_channel(void)
{
    if (memory_channel == NULL) {
        memory_channel = aos_rpc_lmp_setup_channel(cap_chan_memory, "memory");
        if (memory_channel == NULL) {
            debug_printf("aos_rpc_lmp_setup_channel() failed\n");
            return NULL;
        }
    }
    return memory_channel;
}

/**
 * \brief Returns the channel to the process manager.
 */
struct aos_rpc *
aos_rpc_lmp_get_process_channel(void)
{
    if (process_channel == NULL) {
        process_channel = aos_rpc_lmp_setup_channel(cap_chan_process, "process");
        if (process_channel == NULL) {
            debug_printf("aos_rpc_lmp_setup_channel() failed\n");
            return NULL;
        }
    }
    return process_channel;
}

/**
 * \brief Returns the channel to the serial console.
 */
struct aos_rpc *
aos_rpc_lmp_get_serial_channel(void)
{
    if (serial_channel == NULL) {
        serial_channel = aos_rpc_lmp_setup_channel(cap_chan_serial, "serial");
        if (serial_channel == NULL) {
            debug_printf("aos_rpc_lmp_setup_channel() failed\n");
            return NULL;
        }
    }
    return serial_channel;
}
