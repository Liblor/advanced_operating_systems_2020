#include <aos/aos.h>
#include <aos/debug.h>

#include "builtin.h"
#include "../aosh.h"

// builtins
#include "oncore.c"
#include "exit.c"
#include "clear.c"

errval_t builtin_help(int, char **);

/*
 * How to add a builtin:
 * - Create a new file and include "builtin.h"
 * - include the c file of your builtin in this file
 * - Add the main function to the list below
 * - no need to update Hakefile
 */
struct aosh_builtin_descr aosh_builtins[] = {
        {builtin_help,   "help",   "prints this help"},
        {builtin_clear,  "clear",  "clear screen"},
        {builtin_oncore, "oncore", "spawn a dispatcher on a given core"},
        {builtin_exit,   "exit",   "exit shell (Ctrl-d)"},
};

errval_t builtin_help(int argc, char **argv)
{
    printf("list of commands:" ENDL);
    for (int i = 0; i < ARRAY_LENGTH(aosh_builtins); i++) {
        printf("> %s: %s" ENDL, aosh_builtins[i].name, aosh_builtins[i].help);
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