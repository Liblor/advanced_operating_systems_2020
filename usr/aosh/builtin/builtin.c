#include <aos/aos.h>
#include <aos/debug.h>

#include "builtin.h"
#include "../aosh.h"

// builtins
#include "oncore.h"
#include "time.h"

// builtins within this file
errval_t builtin_help(int, char **);
errval_t builtin_clear(int, char **);
errval_t builtin_exit(int, char **);

struct aosh_builtin_descr aosh_builtins[] = {
        {builtin_help,   "help",   "prints this help"},
        {builtin_clear,  "clear",  "clear screen"},
        {builtin_oncore, "oncore", "spawn a dispatcher on a given core"},
        {builtin_time,   "time",   "time a command"},
        {builtin_exit,   "exit",   "exit shell (ctrl-d)"},
};


errval_t builtin_exit(int argc, char **argv)
{
    return AOSH_ERR_EXIT_SHELL;
}

errval_t builtin_clear(int argc, char **argv)
{
    printf("\e[1;1H\e[2J");
    fflush(stdout);
    return SYS_ERR_OK;
}

errval_t builtin_help(int argc, char **argv)
{
    printf("list of commands:" ENDL);
    for (int i = 0; i < ARRAY_LENGTH(aosh_builtins); i++) {
        printf("> "COLOR_RED"%s" COLOR_RESET": %s" ENDL, aosh_builtins[i].name, aosh_builtins[i].help);
    }
    return SYS_ERR_OK;
}

static errval_t builtin_invalid(
        int argc,
        char **argv)
{
    printf("aosh: builtin not found" ENDL);
    for (int i = 0; i < argc; i++) {
        printf("argv[%i] = '%s'" ENDL, i, argv[i]);
    }
    printf("type 'help' for a list of builtins" ENDL);
    return SYS_ERR_OK;
}

errval_t aosh_dispatch_builtin(
        int argc,
        char **argv)
{
    for (int i = 0; i < ARRAY_LENGTH(aosh_builtins); i++) {
        if (strncmp(argv[0], aosh_builtins[i].name, AOSH_READLINE_MAX_LEN) == 0) {
            return aosh_builtins[i].fn(argc, argv);
        }
    }
    return builtin_invalid(argc, argv);
}