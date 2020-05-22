#include <getopt.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <aos/aos_rpc.h>
#include <aos/string.h>
#include <aos/nameserver.h>
#include "nslookup.h"

static void help(int argc, char **argv)
{
    printf("nslookup looks up the service with the given name at the nameserver and prints the PID of the process that service is running on." ENDL);
    printf("usage: %s name" ENDL, argv[0]);
}

static char *nslookup_parse_args(int argc, char **argv)
{
    if (argc == 1) {
        // No name given
        return NULL;
    }

    if (argc > 2) {
        return NULL;
    }

    return argv[1];
}

errval_t builtin_nslookup(int argc, char **argv)
{
    errval_t err;

    // Parse arguments
    char *name = nslookup_parse_args(argc, argv);
    if (name == NULL) {
        printf("Failed to parse arguments.\n");
        help(argc, argv);
        return SYS_ERR_OK;
    }

    // Do lookup
    struct nameservice_chan *chan;
    err = nameservice_lookup(name, (nameservice_chan_t *) &chan);
    if (err_is_fail(err)) {
        printf("nameservice_lookup() failed: %s\n", err_getstring(err));
        return SYS_ERR_OK;
    }

    printf("Service provided by process with PID %llu\n", chan->pid);

    return SYS_ERR_OK;
}
