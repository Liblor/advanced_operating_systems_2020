#include <stdio.h>
#include <stdlib.h>
#include <errors/errno.h>
#include "echo.h"
#include "builtin.h"
#include "fs_utils.h"
#include "../aosh.h"

// TODO: implement if filesystem is available

errval_t builtin_cat(int argc, char **argv) {
    if(argc < 2) {
        printf("usage: %s [file...]\n", argv[0]);
        return SYS_ERR_OK;
    }
    return SYS_ERR_OK;
}

errval_t builtin_ls(int argc, char **argv) {
    return SYS_ERR_OK;
}
errval_t builtin_cd(int argc, char **argv) {
    return SYS_ERR_OK;
}
errval_t builtin_mkdir(int argc, char **argv) {
    return SYS_ERR_OK;
}
errval_t rmdir(int argc, char **argv) {
    return SYS_ERR_OK;
}
errval_t touch(int argc, char **argv) {
    return SYS_ERR_OK;
}