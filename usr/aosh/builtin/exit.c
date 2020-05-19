#include "builtin.h"

errval_t builtin_exit(int argc, char **argv);
errval_t builtin_exit(int argc, char **argv)
{
    return AOS_ERR_AOSH_EXIT;
}
