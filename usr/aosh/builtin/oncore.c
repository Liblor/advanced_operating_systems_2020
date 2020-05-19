#include <getopt.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <aos/aos_rpc.h>

#include "builtin.h"

errval_t builtin_oncore(
        int argc,
        char **argv);

static void help(
        int argc,
        char **argv)
{
    printf("oncore runs a dispatcher on a given core" ENDL);
    printf("usage: %s [-c coreId] name" ENDL, argv[0]);
}

static errval_t parse_args(
        int argc,
        char **argv,
        char **ret_name,
        int *ret_core)
{
    int c;
    optind = 1;
    opterr = 0;

    char *coreId_char = NULL;
    while ((c = getopt(argc, argv, "c:h")) != -1)
        switch (c) {
            case 'c':
                coreId_char = optarg;
                break;
            case 'h': {
                help(argc, argv);
                return AOSH_ERR_INVALID_ARGS;
            }
            case '?':
                if (optopt == 'c') {
                    fprintf(stderr, "Option -%c requires an argument." ENDL, optopt);
                } else {
                    fprintf(stderr, "Unknown argument: %c." ENDL, optopt);
                    help(argc, argv);
                }
                return AOSH_ERR_INVALID_ARGS;;
            default:
                return AOSH_ERR_INVALID_ARGS;;
        }

    if (optind >= argc) {
        fprintf(stderr, "Argument missing: name" ENDL);
        help(argc, argv);
        return AOSH_ERR_INVALID_ARGS;
    }

    int core_id = 0;
    if (coreId_char != NULL) {
        if (isnumber(*coreId_char) == 0) {
            fprintf(stderr, "Option -c requires an integer." ENDL);
            return AOSH_ERR_INVALID_ARGS;
        }
        core_id = atoi(optarg);
    }
    *ret_name = argv[optind];
    *ret_core = core_id;
    return SYS_ERR_OK;
}

errval_t builtin_oncore(
        int argc,
        char **argv)
{
    char *name;
    int core_id;
    errval_t err = parse_args(argc, argv, &name, &core_id);
    if (err == AOSH_ERR_BUILTIN_EXIT_SUCCESS) {
        return SYS_ERR_OK;
    }
    if (!err_is_ok(err)) {
        return SYS_ERR_OK;
    }
    printf("spawning '%s' on core %d" ENDL, name, core_id);
    struct aos_rpc *rpc = aos_rpc_get_process_channel();
    domainid_t pid;
    err = aos_rpc_process_spawn(rpc, name, core_id, &pid);

    if (!err_is_ok(err)) {
        printf("Failed to spawn %s on core %d: %s" ENDL, name, core_id, err_getstring(err));
    }

    return SYS_ERR_OK;
}

