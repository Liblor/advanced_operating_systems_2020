#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/nameserver.h>
#include <grading.h>
#include <aos/systime.h>

//#define PROCESS_SERVER_DEBUG_ON

#if defined(PROCESS_SERVER_DEBUG_ON)
#define PS_DEBUG(x...) debug_printf("[ps]:" x)
#else
#define PS_DEBUG(x...) ((void)0)
#endif

struct process_info {
    char *name;
    domainid_t pid;
    enum process_status status;
    struct process_info *next;
    struct process_info *prev;
};

struct processserver_state {
    struct process_info process_head;
    struct process_info process_tail;
    struct process_info *processlist;
    uint64_t num_proc;
    uint64_t new_pid;

    nameservice_chan_t monitor_chan_list[AOS_CORE_COUNT];
};

static nameservice_chan_t get_monitor_chan(struct processserver_state *server_state, coreid_t cid)
{
    errval_t err;

    assert(server_state != NULL);

    nameservice_chan_t *entry_ptr = &server_state->monitor_chan_list[cid];

    if (*entry_ptr == NULL) {
        char service_name[AOS_RPC_NAMESERVER_MAX_NAME_LENGTH + 1];
        snprintf(service_name, sizeof(service_name), NAMESERVICE_MONITOR "%llu", cid);

        err = nameservice_lookup(service_name, entry_ptr);
        if (err_is_fail(err)) {
            debug_printf("nameservice_lookup() failed: %s\n", err_getstring(err));
            *entry_ptr = NULL;
        }
    }

    return *entry_ptr;
}

static errval_t processserver_send_spawn_local(struct processserver_state *server_state, char *name, coreid_t coreid, domainid_t pid)
{
    errval_t err;

    const uint32_t str_len = MIN(strnlen(name, RPC_LMP_MAX_STR_LEN) + 1, RPC_LMP_MAX_STR_LEN - sizeof(domainid_t)); // no \0 in strlen

    uint8_t send_buf[sizeof(struct rpc_message) + str_len + sizeof(domainid_t)];
    struct rpc_message *req = (struct rpc_message *) &send_buf;

    req->msg.method = Method_Localtask_Spawn_Process;
    req->msg.status = Status_Ok;
    req->cap = NULL_CAP;
    req->msg.payload_length = str_len + sizeof(domainid_t);

    memcpy(req->msg.payload, &pid, sizeof(domainid_t));
    strlcpy(req->msg.payload + sizeof(domainid_t), name, str_len);

    nameservice_chan_t monitor_chan = get_monitor_chan(server_state, coreid);
    if (monitor_chan == NULL) {
        debug_printf("Failed to get monitor service for core %llu.\n", coreid);
        return LIB_ERR_NOT_IMPLEMENTED;
    }

    struct rpc_message *resp = NULL;
    size_t resp_len;

    // Send local task request to monitor on the core where the process should start.
    err = nameservice_rpc(monitor_chan, req, sizeof(send_buf), (void **) &resp, &resp_len, NULL_CAP, NULL_CAP);
    if (err_is_fail(err)) {
        debug_printf("nameservice_rpc():%s\n)", err_getstring(err));
        return err;
    }

    if (resp->msg.status != Status_Ok) {
        return ERR_INVALID_ARGS;
    }

    return SYS_ERR_OK;
}

static void add_process_info(struct processserver_state *server_state, struct process_info *process_info, u_int32_t pid)
{
    server_state->process_tail.prev->next = process_info;
    process_info->prev = server_state->process_tail.prev;
    process_info->next = &server_state->process_tail;
    process_info->pid = pid;
    process_info->status = ProcessStatus_Active;
    server_state->process_tail.prev = process_info;
    server_state->num_proc++;
}

__inline static domainid_t get_new_pid(struct processserver_state *server_state) {
    return server_state->new_pid++;
}

static errval_t add_to_proc_list(struct processserver_state *server_state, char *name, domainid_t pid)
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

    add_process_info(server_state, new_process, pid);
    return SYS_ERR_OK;
}

static inline void init_server_state(struct processserver_state *server_state)
{
    server_state->process_head.next = &server_state->process_tail;
    server_state->process_head.prev = NULL;
    server_state->process_tail.prev = &server_state->process_head;
    server_state->process_tail.next = NULL;
    server_state->processlist = &server_state->process_head;
    server_state->process_head.name = NULL;
    server_state->process_tail.name = NULL;
    server_state->num_proc = 0;
    server_state->new_pid = 100;

    add_to_proc_list(server_state, "init0", PID_INIT_CORE0);
    add_to_proc_list(server_state, "init1", PID_INIT_CORE1);
    add_to_proc_list(server_state, "processserver", PID_PROCESS_SERVER);
}

/**
 * Packs the current running processes into a pid_array
 *
 * @param ret_pid_array contains all pids in this process server state, has to be delted by caller
 * @return errors
 */
static errval_t get_all_pids(struct processserver_state *server_state, size_t *ret_num_pids, domainid_t **ret_pids)
{
    *ret_pids = calloc(1, server_state->num_proc * sizeof(domainid_t));
    if (*ret_pids == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    *ret_num_pids = server_state->num_proc;
    struct process_info *curr = server_state->process_head.next;
    size_t curr_idx = 0;
    while (curr != &(server_state->process_tail)) {
        (*ret_pids)[curr_idx] = curr->pid;
        curr_idx++;
        curr = curr->next;
    }
    assert(curr_idx == server_state->num_proc);
    return SYS_ERR_OK;
}

static errval_t get_name_by_pid(struct processserver_state *server_state, domainid_t pid, char **ret_name) {
    struct process_info *curr = server_state->process_head.next;
    char *found_name = NULL;
    while (curr != &(server_state->process_tail)) {
        if (curr->pid == pid) {
            found_name = curr->name;
            break;
        }
        curr = curr->next;
    }
    if (found_name == NULL) {
        return SYS_ERR_NOT_IMPLEMENTED;
    }
    const size_t name_size = strlen(found_name) + 1;
    *ret_name = malloc(name_size);
    if (*ret_name == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    strncpy(*ret_name, found_name, name_size);

    return SYS_ERR_OK;
}

static errval_t spawn_cb(struct processserver_state *processserver_state, char *name, coreid_t coreid, domainid_t *ret_pid)
{
    errval_t err;

    grading_rpc_handler_process_spawn(name, coreid);

    // TODO: Also store coreid
    domainid_t new_pid = get_new_pid(processserver_state);

    // XXX: we currently use add_to_proc_list to get a ret_pid
    // and ignore the ret_pid set by urpc_send_spawn_request or spawn_load_by_name
    // reason: legacy, spawn_load_by_name does not set pid itself, so
    // add_to_proc_list implemented the behavior

    err = processserver_send_spawn_local(processserver_state, name, coreid, new_pid);
    if (err_is_fail(err)) {
        debug_printf("spawn_load_by_name(): %s\n", err_getstring(err));
        // TODO: If spawn failed, remove the process from the processserver state list.
        return err;
    }

    err = add_to_proc_list(processserver_state, name, new_pid);
    if (err_is_fail(err)) {
        debug_printf("add_to_proc_list(): %s\n", err_getstring(err));
        return err;
    }

    *ret_pid = new_pid;

    return SYS_ERR_OK;
}

static errval_t get_name_cb(struct processserver_state *processserver_state, domainid_t pid, char **ret_name) {
    errval_t err;

    grading_rpc_handler_process_get_name(pid);

    err = get_name_by_pid(processserver_state, pid, ret_name);

    return err;
}

static errval_t get_all_pids_cb(struct processserver_state *processserver_state, size_t *ret_count, domainid_t **ret_pids) {
    errval_t err;

    grading_rpc_handler_process_get_all_pids();

    err = get_all_pids(processserver_state, ret_count, ret_pids);

    return err;
}

inline
static errval_t handle_spawn_process(struct processserver_state *server_state, struct rpc_message_part *rpc_msg_part, struct rpc_message **ret_msg) {
    errval_t err;
    char *name = rpc_msg_part->payload + sizeof(coreid_t);
    coreid_t core = *((coreid_t *)rpc_msg_part->payload);
    domainid_t pid = 0;
    enum rpc_message_status status = Status_Ok;
    // PAGEFAULT
    err = spawn_cb(server_state, name, core, &pid);
    if (err_is_fail(err)) {
        debug_printf("spawn_cb(): %s\n", err_getstring(err));
        status = Spawn_Failed;
    }
    const size_t payload_length = sizeof(struct process_pid_array) + sizeof(domainid_t);
    *ret_msg = malloc(sizeof(struct rpc_message) + payload_length);
    if (*ret_msg == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    struct process_pid_array *pid_array = (struct process_pid_array *) &(*ret_msg)->msg.payload;
    (*ret_msg)->cap = NULL_CAP;
    (*ret_msg)->msg.payload_length = payload_length;
    (*ret_msg)->msg.method = Method_Spawn_Process;
    (*ret_msg)->msg.status = status;
    pid_array->pid_count = 1;
    pid_array->pids[0] = pid;

    return SYS_ERR_OK;
}

inline
static errval_t handle_process_get_name(struct processserver_state *server_state, struct rpc_message_part *rpc_msg_part, struct rpc_message **ret_msg) {
    errval_t  err;
    domainid_t pid = (domainid_t) rpc_msg_part->payload[0];
    enum rpc_message_status status = Status_Ok;
    char *name = NULL;
    err = get_name_cb(server_state, pid, &name);
    if (err_is_fail(err)) {
        status = Process_Get_Name_Failed;
    }
    const size_t payload_length = strnlen(name, RPC_LMP_MAX_STR_LEN) + 1; // strnlen no \0
    *ret_msg = calloc(1, sizeof(struct rpc_message) + payload_length);
    if (*ret_msg == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    char *result_name = (char *) &(*ret_msg)->msg.payload;
    strncpy(result_name, name, payload_length);
    free(name);
    (*ret_msg)->cap = NULL_CAP;
    (*ret_msg)->msg.payload_length = payload_length;
    (*ret_msg)->msg.method = Method_Process_Get_Name;
    (*ret_msg)->msg.status = status;

    return SYS_ERR_OK;
}

inline
static errval_t handle_process_info(
        struct processserver_state *server_state,
        struct rpc_message_part *rpc_msg_part,
        struct rpc_message **ret_msg)
{
    domainid_t pid = (domainid_t) rpc_msg_part->payload[0];

    struct process_info *curr = server_state->process_head.next;
    struct process_info *found = NULL;
    while (curr != &(server_state->process_tail)) {
        if (curr->pid == pid) {
            found = curr;
            break;
        }
        curr = curr->next;
    }
    if (found == NULL) {
        PS_DEBUG("pid %d not found\n", pid);

        *ret_msg = calloc(1, sizeof(struct rpc_message));
        if (*ret_msg == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        (*ret_msg)->cap = NULL_CAP;
        (*ret_msg)->msg.payload_length = 0;
        (*ret_msg)->msg.method = Method_Process_Info;
        (*ret_msg)->msg.status = Status_Error_Process_Pid_Unknown;

    } else {
        // We dont transmit name, use rpc call get_name for it
        struct aos_rpc_process_info_reply reply;
        const size_t payload_len = sizeof(struct aos_rpc_process_info_reply);
        reply.pid = found->pid;
        reply.status = found->status;

        *ret_msg = calloc(1, sizeof(struct rpc_message) + payload_len);
        if (*ret_msg == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        (*ret_msg)->cap = NULL_CAP;
        (*ret_msg)->msg.payload_length = payload_len;
        (*ret_msg)->msg.method = Method_Process_Info;
        (*ret_msg)->msg.status = Status_Ok;
        memcpy(&(*ret_msg)->msg.payload, &reply, payload_len);

    }
    return SYS_ERR_OK;
}

inline
static errval_t handle_process_get_all_pids(struct processserver_state *server_state, struct rpc_message_part *rpc_msg_part, struct rpc_message **ret_msg) {
    errval_t  err;
    size_t pid_count = 0;
    domainid_t *pids = NULL;
    enum rpc_message_status status = Status_Ok;

    err = get_all_pids_cb(server_state, &pid_count, &pids);
    if (err_is_fail(err)) {
        status = Process_Get_All_Pids_Failed;
    }
    // TODO: pid_count sanitation
    const size_t payload_length = sizeof(struct rpc_message) + sizeof(domainid_t) * pid_count + sizeof(size_t);
    *ret_msg = malloc(payload_length);
    if (*ret_msg == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    struct process_pid_array *pid_array = (struct process_pid_array *) &(*ret_msg)->msg.payload;
    pid_array->pid_count = pid_count;
    memcpy(pid_array->pids, pids, sizeof(domainid_t) * pid_count);
    free(pids);

    (*ret_msg)->cap = NULL_CAP;
    (*ret_msg)->msg.payload_length = payload_length;
    (*ret_msg)->msg.method = Method_Process_Get_All_Pids;
    (*ret_msg)->msg.status = status;

    return SYS_ERR_OK;
}

inline
static errval_t handle_process_sign_exit(
        struct processserver_state *server_state,
        struct rpc_message_part *rpc_msg_part,
        struct rpc_message **ret_msg)
{

    if (rpc_msg_part->payload_length < sizeof(domainid_t)) {
        debug_printf("err invalid method size for ping\n");
        return LIB_ERR_LMP_BUFLEN_INVALID;
    }
    domainid_t pid = -1;
    memcpy(&pid, rpc_msg_part->payload, sizeof(domainid_t));
    *ret_msg = NULL;

    struct process_info *found = NULL;
    struct process_info *curr = server_state->process_head.next;
    while (curr != &(server_state->process_tail)) {
        if (curr->pid == pid) {
            found = curr;
            break;
        }
        curr = curr->next;
    }
    if (found == NULL) {
        debug_printf("pid %d not registered\n", pid);
    }
    else {
        // XXX: we keep pid in the list of processes
        found->status = ProcessStatus_Exit;
    }
    return SYS_ERR_OK;
}

static errval_t handle_complete_msg(
        struct processserver_state *server_state,
        struct rpc_message_part *rpc_msg_part,
        struct rpc_message **ret_msg)
{
    switch (rpc_msg_part->method) {
        case Method_Spawn_Process: {
            return handle_spawn_process(server_state, rpc_msg_part, ret_msg);
        }
        case Method_Process_Get_Name: {
            return handle_process_get_name(server_state, rpc_msg_part, ret_msg);
        }
        case Method_Process_Info: {
            return handle_process_info(server_state, rpc_msg_part, ret_msg);
        }
        case Method_Process_Get_All_Pids: {
            return handle_process_get_all_pids(server_state, rpc_msg_part, ret_msg);
        }
        case Method_Process_Signalize_Exit: {
            return handle_process_sign_exit(server_state, rpc_msg_part, ret_msg);
        }
        default:
            // TODO: error on unknown message, introduce new errcode
            debug_printf("Unknown method: %d\n", rpc_msg_part->method);
            break;
    }
    return SYS_ERR_OK;
}

static void service_handler(void *st, void *message, size_t bytes, void **response, size_t *response_bytes, struct capref tx_cap, struct capref *rx_cap)
{
    struct processserver_state *ps = st;
    struct rpc_message *msg = message;
    struct rpc_message *resp_msg = NULL;

    errval_t err;

    err = handle_complete_msg(ps, &msg->msg, &resp_msg);
    if (err_is_fail(err)) {
        debug_printf("handle_complete_msg: %s\n", err_getstring(err));
        return;
    }

    if (resp_msg != NULL){
        *response = resp_msg;
        *response_bytes = sizeof(struct rpc_message) + resp_msg->msg.payload_length;
    } else {
        *response = NULL;
        *response_bytes = 0;
    }
}

int main(int argc, char *argv[])
{
    errval_t err;

    debug_printf("Processserver spawned.\n");

    struct processserver_state *ps = calloc(1, sizeof(struct processserver_state));
    init_server_state(ps);

    err = nameservice_register(NAMESERVICE_PROCESS, service_handler, ps);
    if (err_is_fail(err)) {
        debug_printf("nameservice_register() failed: %s\n", err_getstring(err));
        abort();
    }

    debug_printf("Processserver registered at nameserver.\n");

    debug_printf("Entering message handler loop...\n");
    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
//        err = event_dispatch_non_block(default_ws);
        if (err != LIB_ERR_NO_EVENT && err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
        // XXX: yield leads to much better performance
        thread_yield();
    }
}
