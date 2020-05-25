#include <stdio.h>
#include <stdlib.h>
#include <errors/errno.h>
#include "echo.h"
#include "builtin.h"
#include "fs_utils.h"
#include "../aosh.h"

// TODO: implement if filesystem is available

errval_t builtin_cat(int argc, char **argv) {
    printf("NYI\n");
    return SYS_ERR_OK;

    if(argc < 2) {
        printf("usage: %s [file...]\n", argv[0]);
        return SYS_ERR_OK;
    }
    return SYS_ERR_OK;
}

errval_t builtin_ls(int argc, char **argv) {
    printf("NYI\n");
    return SYS_ERR_OK;
}
errval_t builtin_cd(int argc, char **argv) {
    printf("NYI\n");
    return SYS_ERR_OK;
}
errval_t builtin_mkdir(int argc, char **argv) {
    printf("NYI\n");
    return SYS_ERR_OK;
}
errval_t builtin_rmdir(int argc, char **argv) {
    printf("NYI\n");
    return SYS_ERR_OK;
}
errval_t builtin_touch(int argc, char **argv) {
    printf("NYI\n");
    return SYS_ERR_OK;
}