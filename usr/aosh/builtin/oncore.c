#include <getopt.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <aos/aos_rpc.h>
#include <aos/string.h>
#include "oncore.h"

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
        int *ret_times)
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
    *ret_times = atoi(times);
    return SYS_ERR_OK;
}

errval_t builtin_oncore(
        int argc,
        char **argv)
{
    char *name;
    int core_id = 0;
    int spawn_count = 0;
    errval_t err = parse_args(
            argc,
            argv,
            &name,
            &core_id,
            &spawn_count);
    if (err == AOSH_ERR_BUILTIN_EXIT_SUCCESS) {
        return SYS_ERR_OK;
    }
    if (!err_is_ok(err)) {
        return SYS_ERR_OK;
    }

    printf("spawning '%s' on core '%d' %d time(s)" ENDL, name, core_id, spawn_count);

    struct aos_rpc *rpc = aos_rpc_get_process_channel();
    for (int i = 0; i < spawn_count; i++) {
        printf("spawning %d '%s'\n", i + 1, name);
        domainid_t pid;
        err = aos_rpc_process_spawn(
                rpc,
                name,
                core_id,
                &pid);

        if (!err_is_ok(err)) {
            printf("Failed to spawn %s on core %d: %s" ENDL, name, core_id, err_getstring(err));
            return err;
        }
    }
    return SYS_ERR_OK;
}

