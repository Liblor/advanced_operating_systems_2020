#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

#include <rpc/server/lmp.h>

#include "processserver.h"

static struct rpc_lmp_server server;

static spawn_callback_t spawn_cb = NULL;
static get_name_callback_t get_name_cb = NULL;
static get_all_pids_callback_t get_all_pids_cb = NULL;


static errval_t  handle_complete_msg(struct rpc_message_part *rpc_msg_part, struct rpc_message **ret_msg) {
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
            struct process_pid_array *pid_array = (struct process_pid_array *)&(*ret_msg)->msg.payload;
            pid_array->pid_count = 1;
            pid_array->pids[0] = pid;
            (*ret_msg)->msg.payload_length = payload_length;
            (*ret_msg)->msg.method = Method_Spawn_Process;
            (*ret_msg)->cap = NULL;
            (*ret_msg)->msg.status = status;
            break;
        }
        default: break;
    }

    return SYS_ERR_OK;
}

// TODO refactor ugly copy paste code
static void service_recv_cb(void *arg)
{
    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    struct aos_rpc *rpc = &common_state->rpc;
    struct lmp_chan *lc = &rpc->lc;
    struct processserver_cb_state *state = common_state->shared;

    // accumulate message until full message was transmitted
    // check which message type was sent -> call corresponding callback
    // check if callback is null
    struct capref cap;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;

    errval_t err = lmp_chan_recv(lc, &msg, &cap);
    if (err_is_fail(err) && lmp_err_is_transient(err)) {
        // reregister
        err = lmp_chan_register_recv(lc, get_default_waitset(),
                                     MKCLOSURE(service_recv_cb, arg));
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "");
            return;
        }
    }
    err = lmp_chan_register_recv(lc, get_default_waitset(),
                                 MKCLOSURE(service_recv_cb, arg));
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "");
        return;
    }

    // TODO handle received error
    assert(msg.buf.buflen <= 4);


    if (state->pending_state == EmptyState) {
        struct rpc_message_part *rpc_msg_part = (struct rpc_message_part *)msg.words;
        const size_t complete_size = sizeof(struct rpc_message_part) + rpc_msg_part->payload_length;
        // TODO message sanity check, also overflow
        state->total_length = complete_size;
        state->complete_msg = malloc(complete_size);
        // TODO handle error
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
        state->pending_state = EmptyState;
        // TODO

        struct rpc_message *ret = NULL;
        err = handle_complete_msg(state->complete_msg, &ret);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "cant invoke handle_complete_msg");
            return;
        }
        free(ret);
        free(state->complete_msg);
    }
}



// Initialize channel-specific data.
static void state_init_cb(void *arg)
{
    struct rpc_lmp_handler_state *common_state = (struct rpc_lmp_handler_state *) arg;
    common_state->shared = malloc(sizeof(struct processserver_cb_state));
    __unused struct processserver_cb_state *state = common_state->shared;
}

// Free channel-specific data.
static void state_free_cb(void *arg)
{
}

errval_t processserver_init(
    spawn_callback_t new_spawn_cb,
    get_name_callback_t new_get_name_cb,
    get_all_pids_callback_t new_get_all_pids_cb
)
{
    errval_t err;

    spawn_cb = new_spawn_cb;
    get_name_cb = new_get_name_cb;
    get_all_pids_cb = new_get_all_pids_cb;

    err = rpc_lmp_server_init(&server, cap_chan_process, service_recv_cb, state_init_cb, state_free_cb);
    if (err_is_fail(err)) {
        debug_printf("rpc_lmp_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    return SYS_ERR_OK;
}
