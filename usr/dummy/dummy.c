#include <stdio.h>

#include <aos/aos.h>
#include <aos/nameserver.h>

static char *nslookup_parse_args(int argc, char *argv[])
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

// TODO Move this into a shell builtin
__unused
static errval_t nslookup_main(int argc, char *argv[])
{
    errval_t err;

    // Parse arguments
    char *name = nslookup_parse_args(argc, argv);
    if (name == NULL) {
        debug_printf("Failed to parse arguments.\n");
        return LIB_ERR_NOT_IMPLEMENTED;
    }

    struct nameservice_chan *chan;
    err = nameservice_lookup(name, (nameservice_chan_t *) &chan);
    if (err_is_fail(err)) {
        debug_printf("nameservice_lookup() failed: %s\n", err_getstring(err));
        return LIB_ERR_NOT_IMPLEMENTED;
    }

    debug_printf("Service provided by process with pid %llu\n", chan->pid);

    return SYS_ERR_OK;
}

static char *nslist_parse_args(int argc, char *argv[])
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

// TODO Move this into a shell builtin
__unused
static errval_t nslist_main(int argc, char *argv[])
{
    errval_t err;

    // Parse arguments
    char *query = nslist_parse_args(argc, argv);
    if (query == NULL) {
        debug_printf("Failed to parse arguments.\n");
        return LIB_ERR_NOT_IMPLEMENTED;
    }


    size_t num;
    char *result = NULL;

    err = nameservice_enumerate(query, &num, &result);
    if (err_is_fail(err)) {
        debug_printf("nameservice_enumerate() failed: %s\n", err_getstring(err));
        return LIB_ERR_NOT_IMPLEMENTED;
    }

    if (num == 0) {
        debug_printf("There are no services matching query '%s'.\n", query);
        return LIB_ERR_NOT_IMPLEMENTED;
    }

    if (num == 1) {
        debug_printf("There is %llu service matching query '%s':\n", num, query);
    } else {
        debug_printf("There are %llu services matching query '%s':\n", num, query);
    }

    char *name = result;
    for (int i = 0; i < num; i++) {
        size_t name_len = strlen(name);
        debug_printf("%s\n", name);
        name += name_len + 1;
    }

    return SYS_ERR_OK;
}

int main(int argc, char *argv[])
{
    debug_printf("Dummy spawned\n");

    return EXIT_SUCCESS;
}
