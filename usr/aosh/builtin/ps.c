#include "ps.h"
#include <stdio.h>
#include <stdlib.h>
#include <errors/errno.h>
#include "../aosh.h"
#include <collections/list.h>

errval_t builtin_ps(
        int argc,
        char **argv)
{
    if (argc > 1){
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
    }
    printf("PID\tNAME\n");
    for (int i = 0; i < pid_count; i++) {
        printf("%d \t%s \n", pids[i], collections_list_get_ith_item(pid_list, i));
    }

    err = SYS_ERR_OK;

    free_pid_list:
    free(pids);
    collections_list_release(pid_list);
    return err;
}

