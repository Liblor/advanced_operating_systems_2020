#include <stdio.h>
#include <aos/aos.h>
#include <aos/debug.h>
#include <aos/string.h>

#include "builtin.h"
#include "../aosh.h"

// builtins:
errval_t builtin_help(int, char **);
errval_t builtin_exit(int, char **);
errval_t builtin_clear(int, char **);

static struct aosh_builtin_descr aosh_builtins[] = {
        {builtin_help,  "help",  Aosh_Builtin_Help,  "prints this help"},
        {builtin_clear, "clear", Aosh_Builtin_Clear, "clear screen"},
        {builtin_exit,  "exit",  Aosh_Builtin_Exit,  "exit shell (Ctrl-d)"},
};


errval_t builtin_help(
        int argc,
        char **argv)
{
    printf("list of commands:" ENDL);

    for (int i = 0; i < ARRAY_LENGTH(aosh_builtins); i++) {
        printf("> %s: %s" ENDL, aosh_builtins[i].name, aosh_builtins[i].help);
    }
    return SYS_ERR_OK;
}

errval_t builtin_exit(int argc, char **argv)
{
    return AOS_ERR_AOSH_EXIT;
}

errval_t builtin_clear(int argc, char **argv)
{
    printf("\e[1;1H\e[2J");
    fflush(stdout);
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
    printf("type help for a list of builtins" ENDL);
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

