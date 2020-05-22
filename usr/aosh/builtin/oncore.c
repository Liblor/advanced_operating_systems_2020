#include <getopt.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <aos/aos_rpc.h>
#include <aos/string.h>
#include "oncore.h"
#include "../aosh.h"

static void help(void)
{
    printf("oncore runs a dispatcher on a given core" ENDL);
    printf("usage: oncore [-c coreId] [-t times] name" ENDL);
}


static errval_t parse_args(
        int argc,
        char **argv,
        char **ret_name,
        int *ret_core,
        int *ret_times,
        int *ret_name_ind)
{
    const size_t buf_len = 10;
    char core[buf_len + 1];
    char times[buf_len + 1];

    int c;
    optind = 1;
    opterr = 0;
    optarg = NULL;
    while ((c = getopt(argc, argv, "c:t:h")) != -1)
        switch (c) {
            case 'c':
                snprintf(core, buf_len, "%s", optarg);
                break;
            case 't':
                snprintf(times, buf_len, "%s", optarg);
                break;
            case 'h': {
                help();
                return AOSH_ERR_INVALID_ARGS;
            }
            case '?':
                if (optopt == 'c' || optopt == 'n') {
                    fprintf(stderr, "Option -%c requires an argument." ENDL, optopt);
                    help();
                } else {
                    fprintf(stderr, "Unknown argument: %c." ENDL, optopt);
                    help();
                }
                return AOSH_ERR_INVALID_ARGS;;
            default:
                return AOSH_ERR_INVALID_ARGS;;
        }
    if (optind >= argc) {
        fprintf(stderr, "Argument missing: name" ENDL);
        help();
        return AOSH_ERR_INVALID_ARGS;
    }
    *ret_name = argv[optind];
    *ret_core = atoi(core); // treat invalid input as 0
    int t = atoi(times); // treat invalid input as 1 times
    *ret_times = t <= 0 ? 1 : t;
    *ret_name_ind = optind;
    return SYS_ERR_OK;
}

errval_t builtin_oncore(
        int argc,
        char **argv)
{
    char *name;
    int core_id = 0;
    int spawn_count = 0;
    int name_ind;
    errval_t err = parse_args(
            argc,
            argv,
            &name,
            &core_id,
            &spawn_count,
            &name_ind);
    if (err == AOSH_ERR_BUILTIN_EXIT_SUCCESS) {
        return SYS_ERR_OK;
    }
    if (!err_is_ok(err)) {
        return SYS_ERR_OK;
    }

    char *cmd_args = malloc(AOSH_READLINE_MAX_LEN + 1);
    if (cmd_args == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    int b = 0;
    for (int i = name_ind; i < argc; i++) {
        int a = 0;
        while (*(argv[i] + a) != '\0' && a < AOSH_READLINE_MAX_LEN) {
            cmd_args[b] = *(argv[i] + a);
            b++;
            a++;
        }
        if (a > 0 && i + 1 < argc) {
            cmd_args[b] = ' ';
            b++;
        }
    }
    cmd_args[b] = '\0';
    printf("spawning '%s' on core '%d' %d time(s)" ENDL, cmd_args, core_id, spawn_count);

    struct aos_rpc *rpc = aos_rpc_get_process_channel();
    for (int i = 0; i < spawn_count; i++) {
        printf("spawning %d '%s'\n", i + 1, cmd_args);
        domainid_t pid;
        err = aos_rpc_process_spawn(
                rpc,
                cmd_args,
                core_id,
                &pid);

        if (!err_is_ok(err)) {
            printf("Failed to spawn %s on core %d: %s" ENDL, cmd_args, core_id, err_getstring(err));
            goto free_cmd_args;
        }
    }
    err = SYS_ERR_OK;

    free_cmd_args:
    free(cmd_args);
    return err;
}

