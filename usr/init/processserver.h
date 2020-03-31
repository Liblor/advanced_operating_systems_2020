#ifndef _USR_INIT_PROCESSSERVER_H_
#define _USR_INIT_PROCESSSERVER_H_

#include <aos/aos_rpc.h>

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

typedef errval_t (* spawn_callback_t)(struct processserver_state *processerver_state, char *name, coreid_t coreid, domainid_t *ret_pid);
typedef errval_t (* get_name_callback_t)(struct processserver_state *processerver_state, domainid_t pid, char **ret_name);
typedef errval_t (* get_all_pids_callback_t)(struct processserver_state *processerver_state, size_t *ret_count, domainid_t **ret_pids);

errval_t processserver_init(
    spawn_callback_t new_spawn_cb,
    get_name_callback_t new_get_name_cb,
    get_all_pids_callback_t new_get_all_pids_cb
);


// TODO add remove_from_proc_list

errval_t add_to_proc_list(struct processserver_state *processserver_state, char *name, domainid_t *pid);

errval_t get_name_by_pid(struct processserver_state *processserver_state, domainid_t pid, char **ret_name);

errval_t get_all_pids(struct processserver_state *processserver_state, size_t *ret_num_pids, domainid_t **ret_pids);

#endif
