#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/aos_rpc_lmp_marshal.h>
#include <aos/nameserver.h>
#include <aos/deferred.h>
#include <arch/aarch64/aos/dispatcher_arch.h>

__unused static struct aos_rpc *memory_channel = NULL;

__unused static struct aos_rpc *monitor_channel = NULL;
__unused static nameservice_chan_t init_channel = NULL;
__unused static nameservice_chan_t process_channel = NULL;
__unused static nameservice_chan_t serial_channel = NULL;

// serial session to read from serial port
__unused
static struct serial_channel_priv_data serial_channel_data;

/*
 * Used for setting up the channels. While the init_channel and memory_channel
 * are always initialized by the first thread, the same isn't necessarily true
 * for the other channels.
 */
static struct thread_mutex rpc_lmp_mutex = THREAD_MUTEX_INITIALIZER;

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
    errval_t err;

    err = aos_rpc_init(rpc, RpcTypeLmp);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_init()\n");
        return err;
    }

    lmp_chan_init(&rpc->lmp.chan);

    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    errval_t err;

    assert(rpc != NULL);

    uint8_t send_buf[sizeof(struct rpc_message) + sizeof(num)];

    struct rpc_message *msg = (struct rpc_message *) &send_buf;
    msg->msg.method = Method_Send_Number;
    msg->msg.payload_length = sizeof(num);
    msg->msg.status = Status_Ok;
    msg->cap = NULL_CAP;
    memcpy(msg->msg.payload, &num, sizeof(num));

    if (rpc->type == RpcTypeLmp) {
        err = aos_rpc_lmp_send_message(rpc, msg, LMP_SEND_FLAGS_DEFAULT);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "aos_rpc_lmp_send_message()\n");
            return err;
        }
    } else {
        assert(rpc->type == RpcTypeUmp);
        struct nameservice_chan chan = {
            .name = "",
            .rpc = rpc,
            .pid = 0,
        };
        err = nameservice_rpc(&chan, send_buf, sizeof(send_buf), NULL, NULL, msg->cap, NULL_CAP);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "nameservice_rpc()\n");
            return err;
        }
    }

    return SYS_ERR_OK;
}


errval_t
aos_rpc_lmp_send_string(struct aos_rpc *rpc, const char *string)
{
    errval_t err;

    const uint32_t str_len = MIN(strnlen(string, RPC_LMP_MAX_STR_LEN) + 1,
                                 RPC_LMP_MAX_STR_LEN);  //  strln \0 not included

    uint8_t send_buf[sizeof(struct rpc_message) + str_len];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->msg.method = Method_Send_String;
    msg->msg.payload_length = str_len;
    msg->cap = NULL_CAP;
    msg->msg.status = Status_Ok;
    strlcpy(msg->msg.payload, string, str_len);


    if (rpc->type == RpcTypeLmp) {
        err = aos_rpc_lmp_send_message(rpc, msg, LMP_SEND_FLAGS_DEFAULT);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "aos_rpc_lmp_send_message()\n");
            return err;
        }
    } else {
        assert(rpc->type == RpcTypeUmp);
        struct nameservice_chan chan = {
            .name = "",
            .rpc = rpc,
            .pid = 0,
        };
        err = nameservice_rpc(&chan, send_buf, sizeof(send_buf), NULL, NULL, msg->cap, NULL_CAP);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "nameservice_rpc()\n");
            return err;
        }
    }

    return SYS_ERR_OK;
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

    err = slot_alloc(ret_cap);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    const size_t payload_length = sizeof(bytes) + sizeof(alignment);
    uint8_t send_buf[sizeof(struct rpc_message) + payload_length];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->msg.method = Method_Get_Ram_Cap;
    msg->msg.payload_length = payload_length;
    msg->msg.status = Status_Ok;
    msg->cap = NULL_CAP;
    memcpy(msg->msg.payload, &bytes, sizeof(bytes));
    memcpy(msg->msg.payload + sizeof(bytes), &alignment, sizeof(alignment));

    char message[sizeof(struct rpc_message) + sizeof(size_t)];
    struct rpc_message *recv = (struct rpc_message *) message;
    err = aos_rpc_lmp_send_and_wait_recv_one_no_alloc(rpc, msg, recv, validate_get_ram_cap, *ret_cap);
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
    return err;
}

static errval_t
validate_serial_getchar(struct lmp_recv_msg *msg, enum pending_state state)
{
    if (state == EmptyState) {
        return_err(msg == NULL, "msg is null");
        return_err(sizeof(uint64_t) * msg->buf.buflen < sizeof(struct rpc_message_part),
                   "invalid buflen");
        const struct rpc_message_part *msg_part = (struct rpc_message_part *) msg->words;
        return_err(((msg_part->status != Status_Ok)
                         && msg_part->status != Serial_Getchar_Occupied)
                         && (msg_part->status != Serial_Getchar_Nodata), "status not ok");
        return_err(msg_part->method != Method_Serial_Getchar, "wrong method in response");
    }
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    errval_t err;

    const uint32_t payload_len = sizeof(struct serial_getchar_req);
    const size_t send_buf_size = sizeof(struct rpc_message) + payload_len;
    uint8_t send_buf[send_buf_size];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    assert(rpc->priv_data != NULL);
    struct serial_channel_priv_data *channel_data = rpc->priv_data;

    msg->cap = NULL_CAP;
    msg->msg.method = Method_Serial_Getchar;
    msg->msg.payload_length = payload_len;
    msg->msg.status = Status_Ok;

    struct rpc_message *recv = NULL;
    size_t recv_bytes;

    struct serial_getchar_req payload;
    struct serial_getchar_reply reply;

    // XXX server resets a session on a linebreak
    // so we can retry forever if device is busy.
    // we continue if user presses newline and we acquire session
    for(;;) {
        payload.session = channel_data->read_session;
        memcpy(msg->msg.payload, &payload, sizeof(struct serial_getchar_req));

        if (rpc->type == RpcTypeLmp) {
            err = aos_rpc_lmp_send_and_wait_recv(rpc,
                                                 msg,
                                                 &recv,
                                                 validate_serial_getchar);
            if (lmp_err_is_transient(err)) {
                barrelfish_usleep(AOS_RPC_LMP_SERIAL_GETCHAR_NODATA_SLEEP_US);
                continue;
            }
        } else {
            assert(rpc->type == RpcTypeUmp);
            struct nameservice_chan chan = {
                    .name = "",
                    .rpc = rpc,
                    .pid = 0,
            };
            err = nameservice_rpc(&chan,
                                  msg,
                                  send_buf_size,
                                  (void **) &recv,
                                  &recv_bytes,
                                  msg->cap, NULL_CAP);

            // XXX: ns API does not call validate_serial_getchar
        }
        if (err_is_fail(err)) {
            goto free_recv;
        }

        // always use memcpy when dealing with payload[0] (alignment issues)
        memcpy(&reply, recv->msg.payload, sizeof(struct serial_getchar_reply));

        // update session if we got one from server
        if (reply.session != SERIAL_GETCHAR_SESSION_UNDEF) {
            thread_mutex_lock_nested(&rpc->mutex);
            channel_data->read_session = reply.session;
            thread_mutex_unlock(&rpc->mutex);
        }
        if (recv->msg.status == Status_Ok) {
            // server responded ok, return to user
            break;
        }
        else {
            // server was busy, try again
            free(recv);
            recv = NULL;
            barrelfish_usleep(AOS_RPC_LMP_SERIAL_GETCHAR_NODATA_SLEEP_US);
        }
    }
    if (err_is_fail(err)) {
        goto free_recv;
    }

    *retc = reply.data;
    err = SYS_ERR_OK;

    free_recv:
    free(recv);
    return err;
}

errval_t
aos_rpc_lmp_serial_putchar(struct aos_rpc *rpc, char c)
{
    errval_t err;

    uint8_t send_buf[sizeof(struct rpc_message) + sizeof(char)];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->cap = NULL_CAP;
    msg->msg.method = Method_Serial_Putchar;
    msg->msg.payload_length = sizeof(char);
    msg->msg.status = Status_Ok;
    memcpy(msg->msg.payload, &c, sizeof(char));

    if (rpc->type == RpcTypeLmp) {
        err = aos_rpc_lmp_send_message(rpc, msg, LMP_SEND_FLAGS_DEFAULT);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "aos_rpc_lmp_send_message()\n");
            return err;
        }
    } else {
        assert(rpc->type == RpcTypeUmp);
        struct nameservice_chan chan = {
                .name = "",
                .rpc = rpc,
                .pid = 0,
        };
        err = nameservice_rpc(&chan, send_buf, sizeof(send_buf), NULL, NULL, msg->cap, NULL_CAP);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "nameservice_rpc()\n");
            return err;
        }
    }
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_serial_putstr(struct aos_rpc *rpc, char *str, size_t len)
{
    errval_t err;
    const uint32_t str_len = MIN(len + 1, RPC_LMP_MAX_STR_LEN); // add \0 at the end

    if (len > RPC_LMP_MAX_STR_LEN) {
        debug_printf("truncating len because larger than RPC_LMP_MAX_STR_LEN\n");
    }
    uint8_t send_buf[sizeof(struct rpc_message) + str_len];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->msg.method = Method_Serial_Putstr;
    msg->msg.payload_length = str_len;
    msg->cap = NULL_CAP;
    msg->msg.status = Status_Ok;
    strlcpy(msg->msg.payload, str, str_len);

    if (rpc->type == RpcTypeLmp) {
        err = aos_rpc_lmp_send_message(rpc, msg, LMP_SEND_FLAGS_DEFAULT);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "aos_rpc_lmp_send_message()\n");
            return err;
        }
    } else {
        assert(rpc->type == RpcTypeUmp);
        struct nameservice_chan chan = {
                .name = "",
                .rpc = rpc,
                .pid = 0,
        };
        err = nameservice_rpc(&chan, send_buf, sizeof(send_buf), NULL, NULL, msg->cap, NULL_CAP);
        if (err_is_fail(err)) {
            debug_printf("nameservice_rpc() failed: %s\n", err_getstring(err));
            return err;
        }
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

    assert(rpc != NULL);
    assert(cmdline != NULL);
    assert(newpid != NULL);

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
    size_t recv_bytes;

    if (rpc->type == RpcTypeLmp) {
        err = aos_rpc_lmp_send_and_wait_recv(rpc, send, &recv, validate_process_spawn);
        if (err_is_fail(err)) {
            goto clean_up;
        }
    } else {
        assert(rpc->type == RpcTypeUmp);
        struct nameservice_chan chan = {
            .name = "",
            .rpc = rpc,
            .pid = 0,
        };
        err = nameservice_rpc(&chan, send_buf, sizeof(send_buf), (void **) &recv, &recv_bytes, send->cap, NULL_CAP);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "nameservice_rpc()\n");
            return err;
        }

        // TODO Response is not getting validated here
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
    size_t recv_bytes;

    if (rpc->type == RpcTypeLmp) {
        err = aos_rpc_lmp_send_and_wait_recv(rpc, msg, &recv, validate_process_get_name);
        if (err_is_fail(err)) {
            goto clean_up_recv;
        }
    } else {
        assert(rpc->type == RpcTypeUmp);
        struct nameservice_chan chan = {
            .name = "",
            .rpc = rpc,
            .pid = 0,
        };
        err = nameservice_rpc(&chan, send_buf, sizeof(send_buf), (void **) &recv, &recv_bytes, msg->cap, NULL_CAP);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "nameservice_rpc()\n");
            return err;
        }

        // TODO Response is not getting validated here
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
    size_t recv_bytes;

    if (rpc->type == RpcTypeLmp) {
        err = aos_rpc_lmp_send_and_wait_recv(rpc, msg, &recv, validate_process_get_all_pids);
        if (err_is_fail(err)) {
            goto clean_up;
        }
    } else {
        assert(rpc->type == RpcTypeUmp);
        struct nameservice_chan chan = {
            .name = "",
            .rpc = rpc,
            .pid = 0,
        };
        err = nameservice_rpc(&chan, send_buf, sizeof(send_buf), (void **) &recv, &recv_bytes, msg->cap, NULL_CAP);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "nameservice_rpc()\n");
            return err;
        }

        // TODO Response is not getting validated here
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
aos_rpc_lmp_process_ping(struct aos_rpc *rpc)
{
    errval_t err;

    uint8_t send_buf[sizeof(struct rpc_message) + sizeof(domainid_t)];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    struct dispatcher_generic *disp = get_dispatcher_generic(curdispatcher());
    domainid_t pid = disp->domain_id;

    msg->cap = NULL_CAP;
    msg->msg.method = Method_Process_Ping;
    msg->msg.payload_length = sizeof(domainid_t);
    msg->msg.status = Status_Ok;
    memcpy(msg->msg.payload, &pid, sizeof(domainid_t));

    if (rpc->type == RpcTypeLmp) {
        err = aos_rpc_lmp_send_message(rpc, msg, LMP_SEND_FLAGS_DEFAULT);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "aos_rpc_lmp_send_message()\n");
            return err;
        }
    } else {
        assert(rpc->type == RpcTypeUmp);
        struct nameservice_chan chan = {
                .name = "",
                .rpc = rpc,
                .pid = 0,
        };
        err = nameservice_rpc(&chan, send_buf, sizeof(send_buf), NULL, NULL, msg->cap, NULL_CAP);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "nameservice_rpc()\n");
            return err;
        }
    }
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_get_device_cap(struct aos_rpc *rpc, lpaddr_t paddr, size_t bytes,
                           struct capref *ret_cap)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

static errval_t
validate_ns_register(struct lmp_recv_msg *msg, enum pending_state state)
{
    return validate_recv_header(msg, state, Method_Nameserver_Register);
}

errval_t
aos_rpc_lmp_ns_register(struct aos_rpc *rpc, const char *name, struct aos_rpc *chan_add_client, domainid_t pid)
{
    errval_t err;

    assert(rpc != NULL);
    assert(rpc->type == RpcTypeLmp);
    assert(name != NULL);
    assert(chan_add_client != NULL);
    assert(chan_add_client->type == RpcTypeUmp);

    const size_t name_len = strnlen(name, AOS_RPC_NAMESERVER_MAX_NAME_LENGTH);
    if (name_len == AOS_RPC_NAMESERVER_MAX_NAME_LENGTH) {
        // TODO Proper error
        return LIB_ERR_NOT_IMPLEMENTED;
    }

    const size_t payload_length = sizeof(domainid_t) + AOS_RPC_NAMESERVER_MAX_NAME_LENGTH;
    uint8_t send_buf[sizeof(struct rpc_message) + payload_length];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->msg.method = Method_Nameserver_Register;
    msg->msg.payload_length = payload_length;
    msg->msg.status = Status_Ok;
    msg->cap = chan_add_client->ump.frame_cap;
    memset(msg->msg.payload, 0, payload_length);
    char * const payload_base = msg->msg.payload;
    char *ptr = payload_base;
    memcpy(ptr, name, name_len);
    ptr += AOS_RPC_NAMESERVER_MAX_NAME_LENGTH;
    memcpy(ptr, &pid, sizeof(domainid_t));

    char message[sizeof(struct rpc_message)];
    struct rpc_message *recv = (struct rpc_message *) message;
    err = aos_rpc_lmp_send_and_wait_recv_one_no_alloc(rpc, msg, recv, validate_ns_register, NULL_CAP);
    if (err_is_fail(err)) {
        return err;
    }

    assert(capref_is_null(recv->cap));

    return SYS_ERR_OK;
}

static errval_t
validate_ns_deregister(struct lmp_recv_msg *msg, enum pending_state state)
{
    return validate_recv_header(msg, state, Method_Nameserver_Deregister);
}

errval_t
aos_rpc_lmp_ns_deregister(struct aos_rpc *rpc, const char *name)
{
    errval_t err;

    assert(rpc != NULL);
    assert(rpc->type == RpcTypeLmp);
    assert(name != NULL);

    const size_t name_len = strnlen(name, AOS_RPC_NAMESERVER_MAX_NAME_LENGTH);
    if (name_len == AOS_RPC_NAMESERVER_MAX_NAME_LENGTH) {
        // TODO Proper error
        return LIB_ERR_NOT_IMPLEMENTED;
    }

    const size_t payload_length = AOS_RPC_NAMESERVER_MAX_NAME_LENGTH;
    uint8_t send_buf[sizeof(struct rpc_message) + payload_length];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->msg.method = Method_Nameserver_Deregister;
    msg->msg.payload_length = payload_length;
    msg->msg.status = Status_Ok;
    msg->cap = NULL_CAP;
    memset(msg->msg.payload, 0, payload_length);
    memcpy(msg->msg.payload, name, name_len);

    char message[sizeof(struct rpc_message)];
    struct rpc_message *recv = (struct rpc_message *) message;
    err = aos_rpc_lmp_send_and_wait_recv_one_no_alloc(rpc, msg, recv, validate_ns_deregister, NULL_CAP);
    if (err_is_fail(err)) {
        return err;
    }

    assert(capref_is_null(recv->cap));

    return SYS_ERR_OK;
}

static errval_t
validate_ns_lookup(struct lmp_recv_msg *msg, enum pending_state state)
{
    return validate_recv_header(msg, state, Method_Nameserver_Lookup);
}

errval_t
aos_rpc_lmp_ns_lookup(struct aos_rpc *rpc, const char *name, struct aos_rpc *rpc_service, domainid_t *pid)
{
    errval_t err;

    assert(rpc != NULL);
    assert(rpc->type == RpcTypeLmp);
    assert(name != NULL);

    struct capref ret_cap;
    err = slot_alloc(&ret_cap);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    const size_t name_len = strnlen(name, AOS_RPC_NAMESERVER_MAX_NAME_LENGTH);
    if (name_len == AOS_RPC_NAMESERVER_MAX_NAME_LENGTH) {
        // TODO Proper error
        return LIB_ERR_NOT_IMPLEMENTED;
    }

    const size_t payload_length = AOS_RPC_NAMESERVER_MAX_NAME_LENGTH;
    uint8_t send_buf[sizeof(struct rpc_message) + payload_length];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->msg.method = Method_Nameserver_Lookup;
    msg->msg.payload_length = payload_length;
    msg->msg.status = Status_Ok;
    msg->cap = NULL_CAP;
    memset(msg->msg.payload, 0, payload_length);
    memcpy(msg->msg.payload, name, name_len);

    char message[sizeof(struct rpc_message)];
    struct rpc_message *recv = (struct rpc_message *) message;
    err = aos_rpc_lmp_send_and_wait_recv_one_no_alloc(rpc, msg, recv, validate_ns_lookup, ret_cap);
    if (err_is_fail(err)) {
        return err;
    }

    assert(!capref_is_null(recv->cap));

    memcpy(pid, recv->msg.payload, sizeof(domainid_t));

    err = aos_rpc_ump_init(rpc_service, ret_cap, false);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_init() failed: %s\n", err_getstring(err));
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t
validate_ns_enumerate(struct lmp_recv_msg *msg, enum pending_state state)
{
    return validate_recv_header(msg, state, Method_Nameserver_Enumerate);
}

errval_t aos_rpc_lmp_ns_enumerate(struct aos_rpc *rpc, const char *query, size_t *num, char **result)
{
    errval_t err;

    assert(rpc != NULL);
    assert(rpc->type == RpcTypeLmp);
    assert(query != NULL);

    const size_t query_len = strnlen(query, AOS_RPC_NAMESERVER_MAX_NAME_LENGTH);
    if (query_len == AOS_RPC_NAMESERVER_MAX_NAME_LENGTH) {
        // TODO Proper error
        return LIB_ERR_NOT_IMPLEMENTED;
    }

    const size_t payload_length = AOS_RPC_NAMESERVER_MAX_NAME_LENGTH;
    uint8_t send_buf[sizeof(struct rpc_message) + payload_length];
    struct rpc_message *msg = (struct rpc_message *) &send_buf;

    msg->msg.method = Method_Nameserver_Enumerate;
    msg->msg.payload_length = payload_length;
    msg->msg.status = Status_Ok;
    msg->cap = NULL_CAP;
    memset(msg->msg.payload, 0, payload_length);
    memcpy(msg->msg.payload, query, query_len);

    struct rpc_message *recv = NULL;
    err = aos_rpc_lmp_send_and_wait_recv(rpc, msg, &recv, validate_ns_enumerate);
    if (err_is_fail(err)) {
        return err;
    }

    assert(capref_is_null(recv->cap));

    char * const payload_base = &(recv->msg.payload[0]);
    char *ptr = payload_base;
    memcpy(num, ptr, sizeof(size_t));
    ptr += sizeof(size_t);

    *result = ptr;

    return SYS_ERR_OK;
}

static void
client_recv_open_cb(void *args)
{
    errval_t err;

    struct aos_rpc *rpc = (struct aos_rpc *) args;
    struct lmp_chan *lc = &rpc->lmp.chan;

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

static struct aos_rpc *aos_rpc_lmp_setup_channel(
    struct capref remote_cap,
    const char *service_name
)
{
    errval_t err;

    struct aos_rpc *rpc = calloc(1, sizeof(struct aos_rpc));
    if (rpc == NULL) {
        debug_printf("malloc returned NULL\n");
        goto error;
    }

    err = aos_rpc_lmp_init(rpc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_init()\n");
        goto error;
    }

    struct lmp_chan *lc = &rpc->lmp.chan;

    struct capref cap_ep;
    err = endpoint_create(DEFAULT_LMP_BUF_WORDS, &cap_ep, &lc->endpoint);
    if (err_is_fail(err)) {
        debug_printf("endpoint_create() failed: %s\n", err_getstring(err));
        goto error;
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
        goto error;
    }

    // Allocate receive slot to receive the capability of the service endpoint
    err = lmp_chan_alloc_recv_slot(lc);
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_alloc_recv_slot() failed: %s\n", err_getstring(err));
        goto error;
    }

    uint32_t retries = 0;
    do {
        err = lmp_chan_send0(lc, LMP_SEND_FLAGS_DEFAULT, cap_ep);
        if (lmp_err_is_transient(err)) {
            retries++;
            if (retries >= TRANSIENT_ERR_RETRIES) {
                debug_printf("A transient error occured %u times, retries exceeded\n", retries);
                break;
            }
        }
    } while (lmp_err_is_transient(err));
    if (err_is_fail(err)) {
        debug_printf("lmp_chan_send0() failed: %s\n", err_getstring(err));
        goto error;
    }

    // Wait for the callback to be executed.
    err = event_dispatch(&ws);
    if (err_is_fail(err)) {
        debug_printf("event_dispatch() failed: %s\n", err_getstring(err));
        goto error;
    }

    err = waitset_destroy(&ws);
    if (err_is_fail(err)) {
        debug_printf("waitset_destroy() failed: %s\n", err_getstring(err));
        // We don't have to return NULL, this error is not critical.
    }

    return rpc;

error:
    debug_printf("Error while setting up channel for %s\n", service_name);
    return NULL;
}

static struct aos_rpc *aos_rpc_lmp_get_channel(
    struct aos_rpc **rpc,
    struct capref cap,
    const char *service_name
)
{
    bool was_unset = false;

    thread_mutex_lock_nested(&rpc_lmp_mutex);

    if (*rpc == NULL) {
        was_unset = true;
        *rpc = aos_rpc_lmp_setup_channel(cap, service_name);
    }

    thread_mutex_unlock(&rpc_lmp_mutex);

    if (was_unset && *rpc == NULL) {
        debug_printf("aos_rpc_lmp_setup_channel() failed\n");
    }

    return *rpc;
}

static struct aos_rpc *get_service_channel(nameservice_chan_t *chan, const char *service_name)
{
    errval_t err;

    bool was_unset = false;

    thread_mutex_lock_nested(&rpc_lmp_mutex);

    if (*chan == NULL) {
        was_unset = true;
        err = nameservice_lookup(service_name, chan);
        if (err_is_fail(err)) {
            debug_printf("nameservice_lookup() failed: %s\n", err_getstring(err));
            *chan = NULL;
        }
    }

    thread_mutex_unlock(&rpc_lmp_mutex);

    if (was_unset && *chan == NULL) {
        debug_printf("aos_rpc_lmp_setup_channel() failed\n");
    }

    return (*chan)->rpc;
}

struct aos_rpc *aos_rpc_lmp_get_monitor_channel(void)
{
    return aos_rpc_lmp_get_channel(&monitor_channel, cap_chan_monitor, "monitor");
}

/**
 * \brief Returns the channel to the init dispatcher.
 */
struct aos_rpc *aos_rpc_lmp_get_init_channel(void)
{
    return get_service_channel(&init_channel, NAMESERVICE_INIT);
}

/**
 * \brief Returns the channel to the memory server.
 */
struct aos_rpc *aos_rpc_lmp_get_memory_channel(void)
{
    // XXX: Memory channel is always served by memory server on same core
    return aos_rpc_lmp_get_channel(&memory_channel, cap_chan_memory, "memory");
}

/**
 * \brief Returns the channel to the process manager.
 */
struct aos_rpc *aos_rpc_lmp_get_process_channel(void)
{
    return get_service_channel(&process_channel, NAMESERVICE_PROCESS);
}

/**
 * \brief Returns the channel to the serial console.
 */
struct aos_rpc *aos_rpc_lmp_get_serial_channel(void)
{
    struct aos_rpc *rpc =
            get_service_channel(&serial_channel, NAMESERVICE_SERIAL);

    if (rpc == NULL) {return NULL;}

    // XXX: we store serial specific state in channel
    thread_mutex_lock_nested(&rpc->mutex);
    if (rpc->priv_data == NULL) {
        rpc->priv_data = &serial_channel_data;
        memset(rpc->priv_data, 0, sizeof(struct serial_channel_priv_data));
        serial_channel_data.read_session = SERIAL_GETCHAR_SESSION_UNDEF;
    }
    thread_mutex_unlock(&rpc->mutex);
    return rpc;
}


