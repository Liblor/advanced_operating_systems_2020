#include "builtin.h"

errval_t builtin_exit(int argc, char **argv);
errval_t builtin_exit(int argc, char **argv)
{
    return AOSH_ERR_EXIT_SHELL;
}
