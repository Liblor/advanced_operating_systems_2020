#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

#include <rpc/server/lmp.h>

#include "processserver.h"

static struct rpc_lmp_server server;

static spawn_callback_t spawn_cb = NULL;
static get_name_callback_t get_name_cb = NULL;
static get_all_pids_callback_t get_all_pids_cb = NULL;

static errval_t dummy_spawn_cb(char *name, coreid_t coreid, domainid_t *ret_pid)
{
    *ret_pid = 77;
    return SYS_ERR_OK;
}

static errval_t dummy_get_name(domainid_t pid, char **ret_name) {
    debug_printf("get name for pid: %d\n", pid);
    *ret_name = malloc(100);
    (*ret_name) = "process name";
    return SYS_ERR_OK;
}

static errval_t handle_complete_msg(struct rpc_message_part *rpc_msg_part, struct rpc_message **ret_msg) {
    errval_t err;
    switch (rpc_msg_part->method) {
        case Method_Spawn_Process: {
            // TODO create struct for each msg type
            char *name = rpc_msg_part->payload + sizeof(coreid_t);
            coreid_t core = *((coreid_t *)rpc_msg_part->payload);
            domainid_t pid;
            enum rpc_message_status status = Status_Ok;
            err = spawn_cb(name, core, &pid);
            if (err_is_fail(err)) {
                status = Spawn_Failed;
            }
            const size_t payload_length = sizeof(struct process_pid_array) + sizeof(domainid_t);
            *ret_msg = malloc(sizeof(struct rpc_message) + payload_length);
            if (*ret_msg == NULL) {
                return LIB_ERR_MALLOC_FAIL;
            }
            struct process_pid_array *pid_array = (struct process_pid_array *) &(*ret_msg)->msg.payload;
            (*ret_msg)->cap = NULL;
            (*ret_msg)->msg.payload_length = payload_length;
            (*ret_msg)->msg.method = Method_Spawn_Process;
            (*ret_msg)->msg.status = status;
            pid_array->pid_count = 1;
            pid_array->pids[0] = pid;
            break;
        }

        case Method_Process_Get_Name: {
            HERE;
            debug_printf("size: %d\n", rpc_msg_part->payload_length);
            debug_printf("pid: %p, \n" , rpc_msg_part->payload);
            HERE;
            domainid_t pid = *((domainid_t *) rpc_msg_part->payload);
            HERE;
            enum rpc_message_status status = Status_Ok;
            char *name = NULL;
            HERE;
            err = get_name_cb(pid, &name);
            if (err_is_fail(err)) {
                status = Process_Get_Name_Failed;
            }
            HERE;
            const size_t payload_length = strnlen(name, RPC_LMP_MAX_STR_LEN);
            *ret_msg = malloc(sizeof(struct rpc_message) + payload_length);
            if (*ret_msg == NULL) {
                return LIB_ERR_MALLOC_FAIL;
            }
            HERE;
            char *result_name = (char *) &(*ret_msg)->msg.payload;
            strncpy(result_name, name, payload_length);
            free(name);
            (*ret_msg)->cap = NULL;
            (*ret_msg)->msg.payload_length = payload_length;
            (*ret_msg)->msg.method = Method_Process_Get_Name;
            (*ret_msg)->msg.status = status;
            break;
        }
        default: break;
    }
    return SYS_ERR_OK;
}

static inline
errval_t validate_lmp_header(struct lmp_recv_msg *msg) {
    if (msg->buf.buflen * sizeof(uintptr_t) < sizeof(struct rpc_message_part)) {
        DEBUG_PRINTF("invalid buflen\n");
        return LIB_ERR_LMP_INVALID_RESPONSE;
    }
    struct rpc_message_part *msg_part = (struct rpc_message_part *) msg->words;
    if (msg_part->status != Status_Ok) {
        DEBUG_PRINTF("status not ok\n");
        return LIB_ERR_LMP_INVALID_RESPONSE;
    }
    return SYS_ERR_OK;
}


// TODO refactor ugly copy paste code
static void service_recv_cb(void *arg)
{
    debug_printf("processserver service_recv_cb()\n");
    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    struct aos_rpc *rpc = &common_state->rpc;
    struct lmp_chan *lc = &rpc->lc;
    struct processserver_cb_state *state = common_state->shared;
    struct capref cap;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    errval_t err = lmp_chan_recv(lc, &msg, &cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "");
        return;
    }
    if (state->pending_state == EmptyState) {
        err = validate_lmp_header(&msg);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "invalid input data");
            return;
        }
        struct rpc_message_part *rpc_msg_part = (struct rpc_message_part *)msg.words;
        const size_t complete_size = sizeof(struct rpc_message_part) + rpc_msg_part->payload_length;
        state->total_length = complete_size;
        state->complete_msg = malloc(complete_size);
        debug_printf("malloc %d size\n", complete_size);
        if (state->complete_msg == NULL) {
            DEBUG_ERR(err, "malloc failed");
            return;
        }
        memset(state->complete_msg, 0, complete_size);
        uint64_t to_copy = MIN(LMP_MSG_LENGTH * sizeof(uint64_t), complete_size - state->bytes_received);
        memcpy(state->complete_msg, rpc_msg_part, sizeof(struct rpc_message_part) + to_copy);
        state->bytes_received = to_copy;

    } else if (state->pending_state == DataInTransmit) {
        uint64_t to_copy = MIN(LMP_MSG_LENGTH * sizeof(uint64_t), state->total_length - state->bytes_received);
        memcpy(state->complete_msg->payload + state->bytes_received, (char *) &msg.words[0], to_copy);
        state->bytes_received += to_copy;
    }

    if (state->bytes_received < state->total_length) {
        state->pending_state = DataInTransmit;
    } else {
        // clear state
        state->pending_state = EmptyState;
        state->bytes_received = 0;
        state->total_length = 0;

        struct rpc_message *ret = NULL;
        err = handle_complete_msg(state->complete_msg, &ret);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "cant invoke handle_complete_msg");
            if (ret != NULL) {
                free(ret);
            }
            return;
        }
        err = aos_rpc_lmp_send_message(lc, ret, LMP_SEND_FLAGS_DEFAULT);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "cant reply with message");
        }
        free(ret);
        free(state->complete_msg);
        state->complete_msg = NULL;
    }
}

// Initialize channel-specific data.
static void state_init_cb(void *arg)
{
    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    common_state->shared = malloc(sizeof(struct processserver_cb_state));

    // keep receive callback registered
    common_state->rpc.lc.endpoint->waitset_state.persistent = true;

    struct processserver_cb_state *state = common_state->shared;
    state->pending_state = EmptyState;
    state->bytes_received = 0;
    state->total_length = 0;
    state->complete_msg = NULL;
}

// Free channel-specific data.
static void state_free_cb(void *arg)
{
}

static void add_process_info(struct processserver_state *ps, struct process_info *process_info)
{
    ps->process_tail.prev->next = process_info;
    process_info->prev = ps->process_tail.prev;
    process_info->next = &ps->process_tail;
    ps->process_tail.prev = process_info;
    ps->num_proc++;
}

errval_t add_to_proc_list(struct processserver_state *ps, char *name, domainid_t pid)
{
    struct process_info *new_process = calloc(1, sizeof(struct process_info));
    if (new_process == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    size_t name_size = strlen(name) + 1;    // strlen doesn't include '\0'
    new_process->name = malloc(name_size);
    if (new_process->name == NULL) {
        free(new_process);
        return LIB_ERR_MALLOC_FAIL;
    }
    strncpy(new_process->name, name, name_size);
    new_process->pid = pid;

    add_process_info(ps, new_process);

    return SYS_ERR_OK;
}

/**
 * Packs the current running processes into a pid_array
 *
 * @param ret_pid_array contains all pids in this process server state, has to be delted by caller
 * @return errors
 */
errval_t get_pid_array(struct processserver_state *ps, struct process_pid_array **ret_pid_array)
{
    *ret_pid_array = calloc(1, sizeof(struct process_pid_array) + ps->num_proc * sizeof(domainid_t));
    if (*ret_pid_array == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    (*ret_pid_array)->pid_count = ps->num_proc;
    struct process_info *curr = ps->process_head.next;
    size_t curr_idx = 0;
    while (curr != &(ps->process_tail)) {
        (*ret_pid_array)->pids[curr_idx] = curr->pid;
        curr_idx++;
        curr = curr->next;
    }
    assert(curr_idx == ps->num_proc);
    return SYS_ERR_OK;
}

errval_t get_name_by_pid(struct processserver_state *ps, domainid_t pid, char **ret_name) {
    struct process_info *curr = ps->process_head.next;
    char *found_name = NULL;
    while (curr != &(ps->process_tail)) {
        if (curr->pid == pid) {
            found_name = curr->name;
            break;
        }
        curr = curr->next;
    }
    if (found_name == NULL) {
        return AOS_ERR_PID_NOT_FOUND;
    }
    const size_t name_size = strlen(found_name) + 1;
    *ret_name = malloc(name_size);
    strncpy(*ret_name, found_name, name_size);

    return SYS_ERR_OK;
}

errval_t processserver_init(
        struct processserver_state *processserver_state,
        spawn_callback_t new_spawn_cb,
        get_name_callback_t new_get_name_cb,
        get_all_pids_callback_t new_get_all_pids_cb
)
{
    debug_printf("processserver_init()\n");
    errval_t err;

    processserver_state->process_head.next = &processserver_state->process_tail;
    processserver_state->process_head.prev = NULL;
    processserver_state->process_tail.prev = &processserver_state->process_head;
    processserver_state->process_tail.next = NULL;
    processserver_state->processlist = &processserver_state->process_head;
    processserver_state->process_head.name = NULL;
    processserver_state->process_tail.name = NULL;
    processserver_state->num_proc = 0;

    // TODO is init 0?
    add_to_proc_list(processserver_state, "init", 0);

    spawn_cb = new_spawn_cb;
    get_name_cb = new_get_name_cb;
    get_all_pids_cb = new_get_all_pids_cb;

    // TODO: use dummy spawn
    spawn_cb = dummy_spawn_cb;
    get_name_cb = dummy_get_name;

    err = rpc_lmp_server_init(&server, cap_chan_process, service_recv_cb, state_init_cb, state_free_cb);
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
