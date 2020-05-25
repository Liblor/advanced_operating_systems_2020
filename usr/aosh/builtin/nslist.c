#include <getopt.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <aos/aos_rpc.h>
#include <aos/string.h>
#include <aos/nameserver.h>
#include "nslist.h"

static void help(int argc, char **argv)
{
    printf("nslist lists all services registered at the nameserver that match the given query." ENDL);
    printf("If no argument is given, nslist will list all services registered at the nameserver." ENDL);
    printf("usage: %s query" ENDL, argv[0]);
}

static char *nslist_parse_args(int argc, char **argv)
{
    if (argc == 1) {
        // No query given
        return "";
    }

    if (argc > 2) {
        return NULL;
    }

    return argv[1];
}

errval_t builtin_nslist(int argc, char **argv)
{
    errval_t err;

    // Parse arguments
    char *query = nslist_parse_args(argc, argv);
    if (query == NULL) {
        printf("Failed to parse arguments.\n");
        help(argc, argv);
        return SYS_ERR_OK;
    }

    // Do enumeration
    size_t num;
    char *result = NULL;

    err = nameservice_enumerate(query, &num, &result);
    if (err_is_fail(err)) {
        printf("nameservice_enumerate() failed: %s\n", err_getstring(err));
        return SYS_ERR_OK;
    }

    if (num == 0) {
        printf("There are no services matching query '%s'.\n", query);
        return SYS_ERR_OK;
    }

    if (num == 1) {
        printf("There is %llu service matching query '%s':\n", num, query);
    } else {
        printf("There are %llu services matching query '%s':\n", num, query);
    }

    char *name = result;
    for (int i = 0; i < num; i++) {
        size_t name_len = strlen(name);
        printf("%s\n", name);
        name += name_len + 1;
    }

    return SYS_ERR_OK;
}

