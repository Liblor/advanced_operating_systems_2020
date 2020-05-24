#include "ps.h"
#include <stdio.h>
#include <stdlib.h>
#include <errors/errno.h>
#include "../aosh.h"
#include <collections/list.h>
#include <aos/systime.h>

__inline
static const char *status_to_str(enum process_status status)
{
    switch (status) {
        case ProcessStatus_Active: {
            return "active";
        }
        case ProcessStatus_Init:
            return "init";
        case ProcessStatus_InActive:
            return "inactive";
        default:
            return "unknown";
    }
}

errval_t builtin_ps(
        int argc,
        char **argv)
{
    if (argc > 1) {
        printf("ps -- report a snapshot of spawned dispatchers\n");
        printf("usage: ps\n");
        return SYS_ERR_OK;
    }

    domainid_t *pids = NULL;
    size_t pid_count = -1;

    struct aos_rpc *rpc = aos_rpc_get_process_channel();
    errval_t err = aos_rpc_lmp_process_get_all_pids(rpc, &pids, &pid_count);
    if (err_is_fail(err)) {
        return err;
    }

    collections_listnode *pid_list = NULL;
    collections_list_create(&pid_list, free);

    collections_listnode *pid_list_info = NULL;
    collections_list_create(&pid_list_info, free);

    for (int i = 0; i < pid_count; i++) {
        char *name = NULL;
        err = aos_rpc_lmp_process_get_name(rpc, pids[i], &name);
        if (err_is_fail(err)) {
            goto free_pid_list;
        }
        if (collections_list_insert_tail(pid_list, name) != 0) {
            // something terrible happened with malloc
            err = COLLECTIONS_LIST_INSERT_TAIL_FAILED;
            goto free_pid_list;
        }
        struct aos_rpc_process_info_reply *reply = NULL;
        err = aos_rpc_lmp_process_get_info(rpc, pids[i], &reply);
        if (err_is_fail(err)) {
            goto free_pid_list_info;
        }
        if (collections_list_insert_tail(pid_list_info, reply) != 0) {
            err = COLLECTIONS_LIST_INSERT_TAIL_FAILED;
            goto free_pid_list_info;
        }
    }

    int w_pid = 6;
    int w_status = 10;
    int w_ping = 20;
    printf("%*s%*s%*s\t%s\n", w_pid, "PID", w_status, "STATUS", w_ping, "LAST_PING_MS_AGO", "NAME");
    uint64_t now = systime_to_ns(systime_now()) / 1000 / 1000;
    for (int i = 0; i < pid_count; i++) {
        struct aos_rpc_process_info_reply *reply
                = collections_list_get_ith_item(pid_list_info, i);
        if (reply->status != ProcessStatus_InActive) {
            char *name = collections_list_get_ith_item(pid_list, i);
            printf("%*d%*s%*zu\t%s\n",
                   w_pid, pids[i],
                   w_status, status_to_str(reply->status),
                   w_ping, now - systime_to_ns(reply->last_ping) / 1000 / 1000,
                   name);
        }
    }
    for (int i = 0; i < pid_count; i++) {
        struct aos_rpc_process_info_reply *reply
                = collections_list_get_ith_item(pid_list_info, i);
        if (reply->status == ProcessStatus_InActive) {
            char *name = collections_list_get_ith_item(pid_list, i);
            printf("%*d%*s%*zu\t%s\n",
                   w_pid, pids[i],
                   w_status, status_to_str(reply->status),
                   w_ping, now - systime_to_ns(reply->last_ping) / 1000 / 1000,
                   name);
        }
    }

    err = SYS_ERR_OK;

    free_pid_list_info:
    collections_list_release(pid_list_info);

    free_pid_list:
    free(pids);
    collections_list_release(pid_list);

    return err;
}

