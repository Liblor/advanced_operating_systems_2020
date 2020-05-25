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
        case ProcessStatus_Exit:
            return "exit";
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
    int w_pid = 6;
    int w_status = 10;
    printf("%*s%*s\t%s\n", w_pid, "PID", w_status, "STATUS",  "NAME");

    for (int i = 0; i < pid_count; i++) {
        char *name = NULL;
        err = aos_rpc_lmp_process_get_name(rpc, pids[i], &name);
        if (err_is_fail(err)) {
            goto free_pid_list;
        }

        struct aos_rpc_process_info_reply *reply = NULL;
        err = aos_rpc_lmp_process_get_info(rpc, pids[i], &reply);
        if (err_is_fail(err)) {
            free(name);
            goto free_pid_list;
        }

        printf("%*d%*s\t%s\n",
               w_pid, pids[i],
               w_status, status_to_str(reply->status),
               name);

        free(name);
        free(reply);
    }

    err = SYS_ERR_OK;
    free_pid_list:
    free(pids);

    return err;
}

