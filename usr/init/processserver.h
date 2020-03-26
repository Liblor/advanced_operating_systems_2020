#ifndef _USR_INIT_PROCESSSERVER_H_
#define _USR_INIT_PROCESSSERVER_H_

#include <aos/aos_rpc.h>

typedef errval_t (* spawn_callback_t)(char *name, coreid_t coreid, domainid_t *ret_pid);
typedef errval_t (* get_name_callback_t)(domainid_t pid, char **ret_name);
typedef errval_t (* get_all_pids_callback_t)(size_t *ret_count, domainid_t **ret_pids);

struct processserver_cb_state {
    size_t bytes_received; ///< How much was read from the client already.
    size_t total_length;
    enum pending_state pending_state;
    struct rpc_message_part *complete_msg;
};

// XXX: we should have some generic datastructure that is more efficient
struct process_info {
    char *name;
    domainid_t pid;
    struct process_info *next;
    struct process_info *prev;
};

struct processserver_state {
    struct process_info process_head;
    struct process_info process_tail;
    struct process_info *processlist;
    uint64_t num_proc;
};

// TODO add remove_from_proc_list

errval_t add_to_proc_list(struct processserver_state *ps, char *name, domainid_t pid);

errval_t get_all_pids(struct processserver_state *ps, size_t *ret_num_pids, domainid_t **ret_pids);

errval_t get_name_by_pid(struct processserver_state *ps, domainid_t pid, char **ret_name);

errval_t processserver_init(
        struct processserver_state *processserver_state,
        spawn_callback_t new_spawn_cb,
        get_name_callback_t new_get_name_cb,
        get_all_pids_callback_t new_get_all_pids_cb
);

#endif
