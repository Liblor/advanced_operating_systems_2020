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

errval_t processserver_init(
    spawn_callback_t spawn_cb,
    get_name_callback_t get_name_cb,
    get_all_pids_callback_t get_all_pids_cb
);

#endif
