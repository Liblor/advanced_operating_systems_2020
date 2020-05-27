#include <aos/aos.h>
#include <aos/debug.h>

#include "builtin.h"
#include "../aosh.h"

// builtins
#include "oncore.h"
#include "time.h"
#include "nslookup.h"
#include "nslist.h"
#include "echo.h"
#include "ps.h"
#include "fs_utils.h"
#include "domain_info.h"
#include "rpctest.h"
#include "run_memtest.h"
#include "color.h"

// builtins within this file
errval_t builtin_help(int, char **);
errval_t builtin_clear(int, char **);
errval_t builtin_exit(int, char **);

struct aosh_builtin_descr aosh_builtins[] = {
        {builtin_help,     "help",     "prints this help"},
        {builtin_clear,    "clear",    "clear screen"},
        {builtin_echo,    "echo",    "display a line of text"},
        {builtin_oncore,   "oncore",   "spawn a dispatcher on a given core"},
        {builtin_time,     "time",     "time a command"},
        {builtin_ps,     "ps",     "report a snapshot of spawned processes"},
        {builtin_pid,     "pid",     "show my pid"},
        {builtin_coreid,     "coreid",     "show my coreid"},
        {builtin_rpctest,     "rpctest",     "testsuite for rpc-tests"},
        {builtin_run_memtest,     "run_memtest",     "runs memory write/read test"},
        {builtin_color,     "color",     "color test in terminal"},
        {builtin_nslookup, "nslookup", "lookup a service at the nameserver"},
        {builtin_nslist,   "nslist",   "list services registered at the nameserver"},
        {builtin_ls,   "ls",   "list directory contents"},
        {builtin_cat,   "cat",   "concatenate files and print on the standard output"},
        {builtin_cd,   "cd",   "change directory"},
        {builtin_pwd,   "pwd",   "print current working directory"},
        {builtin_rm,   "rm",   "remove file"},
        {builtin_mkdir,   "mkdir",   "make directory"},
        {builtin_rmdir,   "rmdir",   "remove directory"},
        {builtin_touch,   "touch",   "create file"},
        {builtin_exit,     "exit",     "exit shell (ctrl-d)"},
};

size_t aosh_builtins_len = ARRAY_LENGTH(aosh_builtins);

char *aosh_pwd = MOUNTPOINT;

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
