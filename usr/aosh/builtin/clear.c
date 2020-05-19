#include "builtin.h"

errval_t builtin_clear(int argc, char **argv);

errval_t builtin_clear(int argc, char **argv)
{
    printf("\e[1;1H\e[2J");
    fflush(stdout);
    return SYS_ERR_OK;
}
