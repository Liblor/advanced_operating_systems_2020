#include <stdio.h>
#include <stdlib.h>
#include <errors/errno.h>
#include "echo.h"
#include "../aosh.h"

errval_t builtin_echo(
        int argc,
        char **argv)
{
    argv++;
    argc--;
    char *out = malloc(AOSH_READLINE_MAX_LEN + 1);
    if (out == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    int b = 0;
    for (int i = 0; i < argc; i++) {
        int a = 0;
        while (*(argv[i] + a) != '\0' && a < AOSH_READLINE_MAX_LEN) {
            out[b] = *(argv[i] + a);
            b++;
            a++;
        }
        if (a > 0 && i + 1 < argc) {
            out[b] = ' ';
            b++;
        }
    }
    out[b] = '\0';
    printf("%s\n", out);
    free(out);
    return SYS_ERR_OK;
}
