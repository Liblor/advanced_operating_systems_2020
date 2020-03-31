#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/aos_rpc_lmp_marshal.h>

static struct aos_rpc *init_channel = NULL;
static struct aos_rpc *memory_channel = NULL;
static struct aos_rpc *process_channel = NULL;
static struct aos_rpc *serial_channel = NULL;

static inline errval_t
validate_recv_header(struct lmp_recv_msg *msg, enum pending_state state, enum rpc_message_method method) {
    if (state == EmptyState) {
        return_err(msg == NULL, "msg is null");
        return_err(sizeof(uint64_t) * msg->buf.buflen < sizeof(struct rpc_message_part), "invalid buflen");
        const struct rpc_message_part *msg_part = (struct rpc_message_part *) msg->words;
        return_err(msg_part->status != Status_Ok, "status not ok");
        return_err(msg_part->method != method, "wrong method in response");
    }
    return SYS_ERR_OK;
}

void aos_rpc_lmp_handler_print(char *string, uintptr_t *val, struct capref *cap) {
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

errval_t aos_rpc_lmp_init(struct aos_rpc *rpc) {
    lmp_chan_init(&rpc->lc);
    struct aos_rpc_lmp *rpc_lmp = malloc(sizeof(struct aos_rpc_lmp));
    if (rpc_lmp == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    memset(rpc_lmp, 0, sizeof(struct aos_rpc_lmp));
    waitset_init(&rpc_lmp->ws);
    rpc_lmp->err = SYS_ERR_OK;
    rpc->lmp = rpc_lmp;

    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_send_number(struct aos_rpc *rpc, uintptr_t num) {
    struct rpc_message *msg = malloc(sizeof(struct rpc_message) + sizeof(num));
    if (msg == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->msg.method = Method_Send_Number;
    msg->msg.payload_length = sizeof(num);
    msg->msg.status = Status_Ok;
    msg->cap = NULL_CAP;
    memcpy(msg->msg.payload, &num, sizeof(num));

    errval_t err = aos_rpc_lmp_send_message(&rpc->lc, msg, LMP_SEND_FLAGS_DEFAULT);
    free(msg);
    return err;
}

errval_t
aos_rpc_lmp_send_string(struct aos_rpc *rpc, const char *string) {
    const uint32_t str_len = MIN(strlen(string) + 1, RPC_LMP_MAX_STR_LEN);
    struct rpc_message *msg = malloc(sizeof(struct rpc_message) + str_len);
    if (msg == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->msg.method = Method_Send_String;
    msg->msg.payload_length = str_len;
    msg->cap = NULL_CAP;
    msg->msg.status = Status_Ok;
    strncpy(msg->msg.payload, string, str_len);

    errval_t err = aos_rpc_lmp_send_message(&rpc->lc, msg, LMP_SEND_FLAGS_DEFAULT);
    free(msg);
    return err;
}

static void client_ram_cb(void *arg) {
    debug_printf("client_ram_cb(...)\n");
    struct aos_rpc *rpc = arg;
    struct client_ram_state *ram_state = rpc->lmp->shared;
    struct aos_rpc_lmp *lmp = rpc->lmp;

    struct lmp_chan *lc = &rpc->lc;

    struct capref cap;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    errval_t err = lmp_chan_recv(lc, &msg, &cap);
    if (err_is_fail(err) && lmp_err_is_transient(err)) {
        // reregister
        err = lmp_chan_register_recv(lc, &lmp->ws,
                                     MKCLOSURE(client_ram_cb, arg));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "");
            lmp->err = err;
            return;
        }
    }
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "");
        lmp->err = err;
        return;
    }
    bool buflen_invalid = msg.buf.buflen * sizeof(uintptr_t) < sizeof(struct rpc_message_part);
    return_with_err(buflen_invalid, lmp, "invalid buflen");

    struct rpc_message_part *msg_part = (struct rpc_message_part *) msg.words;

    return_with_err(msg_part->status != Status_Ok, lmp, "status not ok");
    return_with_err(msg_part->method != Method_Get_Ram_Cap, lmp, "wrong method in response");
    return_with_err(msg_part->payload_length != sizeof(size_t), lmp, "invalid payload len");

    memcpy(&ram_state->bytes, msg_part->payload, sizeof(size_t));
    // TODO Free recv slot if cap is NULL_CAP
    ram_state->cap = cap;
    lmp->err = SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                        struct capref *ret_cap, size_t *ret_bytes) {
    errval_t err;

    // create request message
    const size_t payload_length = sizeof(bytes) + sizeof(alignment);
    struct rpc_message *msg = malloc(sizeof(struct rpc_message) + payload_length);
    if (msg == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->msg.method = Method_Get_Ram_Cap;
    msg->msg.payload_length = payload_length;
    msg->msg.status = Status_Ok;
    msg->cap = NULL_CAP;
    memcpy(msg->msg.payload, &bytes, sizeof(bytes));
    memcpy(msg->msg.payload + sizeof(bytes), &alignment, sizeof(alignment));

    // register receive handler state
    err = lmp_chan_register_recv(&rpc->lc, &rpc->lmp->ws,
                                 MKCLOSURE(client_ram_cb, rpc));
    if (err_is_fail(err)) {
        goto clean_up;
    }

    err = lmp_chan_alloc_recv_slot(&rpc->lc);
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_alloc_recv_slot() failed: %s\n", err_getstring(err));
        err = LIB_ERR_LMP_ALLOC_RECV_SLOT;
        goto clean_up;
    }

    // send ram request
    err = aos_rpc_lmp_send_message(&rpc->lc, msg, LMP_SEND_FLAGS_DEFAULT);
    if (err_is_fail(err)) {
        goto clean_up;
    }

    // wait for response
    err = event_dispatch(&rpc->lmp->ws);
    if (err_is_fail(err)) {
        goto clean_up;
    }
    if (err_is_fail(rpc->lmp->err)) {
        err = rpc->lmp->err;
        goto clean_up;
    }

    // save response
    struct client_ram_state *ram_state = rpc->lmp->shared;
    *ret_cap = ram_state->cap;
    if (ret_bytes != NULL) {
        *ret_bytes = ram_state->bytes;
    }

    err = SYS_ERR_OK;
    goto clean_up;

    clean_up:
    free(msg);
    return err;
}

static
void client_serial_cb(void *arg) {
    struct aos_rpc *rpc = (struct aos_rpc *) arg;
    struct lmp_chan *lc = &rpc->lc;
    struct aos_rpc_lmp *lmp = rpc->lmp;
    struct client_serial_state *state = (struct client_serial_state *) lmp->shared;

    struct capref cap;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    errval_t err = lmp_chan_recv(lc, &msg, &cap);
    if (err_is_fail(err) && lmp_err_is_transient(err)) {
        // reregister
        err = lmp_chan_register_recv(lc, &lmp->ws, MKCLOSURE(client_serial_cb, arg));
        if (err_is_fail(err)) {
            lmp->err = LIB_ERR_CHAN_REGISTER_RECV;
            return;
        }
    } else if (err_is_fail(err)) {
        lmp->err = err;
        return;
    }
    bool buflen_invalid = msg.buf.buflen * sizeof(uintptr_t) < sizeof(struct rpc_message_part);
    return_with_err(buflen_invalid, lmp, "invalid buflen");

    struct rpc_message_part *msg_part = (struct rpc_message_part *) msg.words;

    return_with_err(msg_part->status != Status_Ok, lmp, "status not ok");
    return_with_err(msg_part->method != Method_Serial_Getchar, lmp, "wrong method in response");
    return_with_err(msg_part->payload_length != 1, lmp, "invalid payload len");

    state->c_recv = (char) msg_part->payload[0];
    lmp->err = SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_serial_getchar(struct aos_rpc *rpc, char *retc) {
    assert(rpc->lmp->shared != NULL);
    struct rpc_message *msg = malloc(sizeof(struct rpc_message));
    if (msg == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->cap = NULL_CAP;
    msg->msg.method = Method_Serial_Getchar;
    msg->msg.payload_length = 0;
    msg->msg.status = Status_Ok;

    errval_t err = aos_rpc_lmp_send_message(&rpc->lc, msg, LMP_SEND_FLAGS_DEFAULT);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_send_message failed\n");
        goto clean_up_msg;
    }

    struct aos_rpc_lmp *lmp = (struct aos_rpc_lmp *) rpc->lmp;
    err = lmp_chan_register_recv(&rpc->lc, &lmp->ws, MKCLOSURE(client_serial_cb, rpc));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_chan_register_recv failed");
        goto clean_up_msg;
    }
    err = event_dispatch(&lmp->ws);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "event_dispatch failed");
        goto clean_up_msg;
    }
    if (err_is_fail(lmp->err)) {
        err = lmp->err;
        DEBUG_ERR(err, "error during receive");
        goto clean_up_msg;
    }
    struct client_serial_state *state = (struct client_serial_state *) rpc->lmp->shared;
    *retc = state->c_recv;

    err = SYS_ERR_OK;
    goto clean_up_msg;

    clean_up_msg:
    free(msg);
    DEBUG_ERR(err, "aos_rpc_lmp_serial_getchar failed");
    return err;
}

errval_t
aos_rpc_lmp_serial_putchar(struct aos_rpc *rpc, char c) {
    assert(rpc->lmp->shared != NULL);
    // TODO Why is a malloc used here?
    struct rpc_message *msg = malloc(sizeof(struct rpc_message) + sizeof(c));
    if (msg == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->cap = NULL_CAP;
    msg->msg.method = Method_Serial_Putchar;
    msg->msg.payload_length = sizeof(c);
    msg->msg.status = Status_Ok;
    msg->msg.payload[0] = c;

    errval_t err = aos_rpc_lmp_send_message(&rpc->lc, msg, LMP_SEND_FLAGS_DEFAULT);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "lmp_send_message failed\n");
        goto clean_up_msg;
    }
    return SYS_ERR_OK;

    clean_up_msg:
    free(msg);
    return err;
}

static errval_t validate_process_spawn(struct lmp_recv_msg *msg, enum pending_state state) {
    errval_t err = validate_recv_header(msg, state, Method_Spawn_Process);
    if (state == EmptyState && err_is_ok(err)) {
        const struct rpc_message_part *msg_part = (struct rpc_message_part *) msg->words;
        return_err(msg_part->payload_length != sizeof(size_t) + sizeof(domainid_t), "invalid payload len");
    }
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_process_spawn(struct aos_rpc *rpc, char *cmdline,
                          coreid_t core, domainid_t *newpid) {
    errval_t err;
    const uint32_t str_len = MIN(strlen(cmdline) + 1, RPC_LMP_MAX_STR_LEN);
    struct rpc_message *send = malloc(sizeof(struct rpc_message) + str_len + sizeof(core));
    if (send == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    send->msg.method = Method_Spawn_Process;
    send->msg.payload_length = sizeof(core) + str_len;
    send->cap = NULL_CAP;
    send->msg.status = Status_Ok;
    memcpy(send->msg.payload, &core, sizeof(core));
    memcpy(send->msg.payload + sizeof(core), cmdline, str_len);

    struct rpc_message *recv = NULL;
    err = aos_rpc_lmp_send_and_wait_recv(rpc, send, &recv, validate_process_spawn);
    if (err_is_fail(err)) {
        goto clean_up_msg;
    }

    struct process_pid_array *pid_array = (struct process_pid_array *) &recv->msg.payload;
    *newpid = pid_array->pids[0];

    assert(pid_array->pid_count == 1);
    err = SYS_ERR_OK;

    clean_up_msg:
    if (recv != NULL && recv->msg.payload != NULL) {
        free(recv);
    }
    free(send);

    return err;
}

static errval_t
validate_process_get_name(struct lmp_recv_msg *msg, enum pending_state state) {
    return validate_recv_header(msg, state, Method_Process_Get_Name);
}

errval_t
aos_rpc_lmp_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name) {
    errval_t err;
    struct rpc_message *msg = malloc(sizeof(struct rpc_message) + sizeof(pid));
    if (msg == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->cap = NULL_CAP;
    msg->msg.method = Method_Process_Get_Name;
    msg->msg.payload_length = sizeof(pid);
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
    memcpy(*name, recv->msg.payload, recv->msg.payload_length);
    err = SYS_ERR_OK;

    goto clean_up_recv;

    clean_up_recv:
    free(recv);
    free(msg);

    return err;
}

static errval_t
validate_process_get_all_pids(struct lmp_recv_msg *msg, enum pending_state state) {
    return validate_recv_header(msg, state, Method_Process_Get_All_Pids);
}

errval_t
aos_rpc_lmp_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                 size_t *pid_count) {
    errval_t err;
    struct rpc_message *msg = malloc(sizeof(struct rpc_message));
    if (msg == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
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

    const size_t total_length = *pid_count * sizeof(domainid_t); // TODO: sanitize pid_count
    *pids = malloc(total_length);
    if (*pids == NULL) {
        goto clean_up;
    }
    memcpy(*pids, pid_array->pids, total_length);

    err = SYS_ERR_OK;
    goto clean_up;

    clean_up:
    free(recv);
    free(msg);
    return err;
}

errval_t
aos_rpc_lmp_get_device_cap(struct aos_rpc *rpc, lpaddr_t paddr, size_t bytes,
                           struct capref *ret_cap) {
    return LIB_ERR_NOT_IMPLEMENTED;
}

static void client_recv_open_cb(void *args) {
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

static struct aos_rpc *aos_rpc_lmp_setup_channel(struct capref remote_cap, const char *service_name) {
    errval_t err;

    debug_printf("Setting up a new channel to %s.\n", service_name);

    struct aos_rpc *rpc = malloc(sizeof(struct aos_rpc));
    if (rpc == NULL) {
        return NULL;
    }
    err = aos_rpc_lmp_init(rpc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "error in aos_rpc_lmp_init");
        return NULL;
    }

    struct lmp_chan *lc = &rpc->lc;

    struct capref cap_ep;
    err = endpoint_create(DEFAULT_LMP_BUF_WORDS, &cap_ep, &lc->endpoint);
    if (err_is_fail(err)) {
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
        debug_printf("lmp_chan_register_recv() failed: %s\n", err_getstring(err));
        return NULL;
    }

    // Allocate receive slot to receive the capability of the service endpoint
    err = lmp_chan_alloc_recv_slot(lc);
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_alloc_recv_slot() failed: %s\n", err_getstring(err));
        return NULL;
    }

    do {
        err = lmp_chan_send0(lc, LMP_SEND_FLAGS_DEFAULT, cap_ep);
    } while (lmp_err_is_transient(err));
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_send0() failed: %s\n", err_getstring(err));
        return NULL;
    }

    // Wait for the callback to be executed.
    err = event_dispatch(&ws);
    if (err_is_fail(err)) {
        debug_printf("event_dispatch() failed: %s\n", err_getstring(err));
        return NULL;
    }

    err = waitset_destroy(&ws);
    if (err_is_fail(err)) {
        debug_printf("waitset_destroy() failed: %s\n", err_getstring(err));
        // We don't have to return NULL, this error is not critical.
    }

    return rpc;
}

/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_lmp_get_init_channel(void) {
    if (init_channel == NULL) {
        init_channel = aos_rpc_lmp_setup_channel(cap_chan_init, "init");
        init_channel->lmp->shared = NULL; // we dont need state
    }

    return init_channel;
}

/**
 * \brief Returns the channel to the memory server.
 */
struct aos_rpc *aos_rpc_lmp_get_memory_channel(void) {
    if (memory_channel == NULL) {
        memory_channel = aos_rpc_lmp_setup_channel(cap_chan_memory, "memory");

        struct client_ram_state *ram_state = malloc(sizeof(struct client_ram_state));
        if (ram_state == NULL) {
            DEBUG_ERR(LIB_ERR_MALLOC_FAIL, "malloc failed");
            return NULL;
        }
        memory_channel->lmp->shared = ram_state;
    }

    return memory_channel;
}

/**
 * \brief Returns the channel to the process manager.
 */
struct aos_rpc *aos_rpc_lmp_get_process_channel(void) {
    if (process_channel == NULL) {
        process_channel = aos_rpc_lmp_setup_channel(cap_chan_process, "process");

        struct client_process_state *state = malloc(sizeof(struct client_process_state));
        if (state == NULL) {
            DEBUG_ERR(LIB_ERR_MALLOC_FAIL, "malloc failed");
            return NULL;
        }
        process_channel->lmp->shared = state;
    }

    return process_channel;
}

/**
 * \brief Returns the channel to the serial console.
 */
struct aos_rpc *aos_rpc_lmp_get_serial_channel(void) {
    if (serial_channel == NULL) {
        serial_channel = aos_rpc_lmp_setup_channel(cap_chan_serial, "serial");
        struct client_serial_state *state = malloc(sizeof(struct client_serial_state));
        if (state == NULL) {
            DEBUG_ERR(LIB_ERR_MALLOC_FAIL, "malloc failed");
            return NULL;
        }
        serial_channel->lmp->shared = state;
    }

    return serial_channel;
}
