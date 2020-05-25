#include <stdio.h>
#include <stdlib.h>
#include <errors/errno.h>
#include "echo.h"
#include "builtin.h"
#include "fs_utils.h"
#include "../aosh.h"
#include <fs/fs.h>
#include <aos/nameserver.h>

static bool fs_init = false;

inline static errval_t ensure_init(void){
    errval_t err = SYS_ERR_OK;
    if (!fs_init) {
        nameservice_chan_t nschan;
        err = nameservice_lookup(NAMESERVICE_BLOCKDRIVER, &nschan);
        if (err_is_fail(err)) {
            debug_printf("%s not active. Did you start it?\n", NAMESERVICE_BLOCKDRIVER);
            return AOSH_ERR_BUILTIN_EXIT_FAIL;
        }
        err = filesystem_init();
        if (err_is_ok(err)) {
            fs_init = true;
        }
    }
    return err;
}

static errval_t cat_file(char *file)
{
    int res = 0;
    FILE *f = fopen(file, "r");
    if (f == NULL) {
        return FS_ERR_OPEN;
    }
    res = fseek (f , 0 , SEEK_END);
    if (res) {
        return FS_ERR_INVALID_FH;
    }
    size_t filesize = ftell(f);
    rewind (f);
    printf("File size is %zu\n", filesize);

    char *buf = calloc(filesize + 2, sizeof(char));
    if (buf == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    fread(buf, 1, filesize, f);
    printf("%s\n", buf);
    free(buf);
    return SYS_ERR_OK;
}

errval_t builtin_cat(int argc, char **argv) {
    errval_t err;
    err = ensure_init();
    if (err_is_fail(err)) {return err;}

    if(argc < 2) {
        printf("usage: %s [file...]\n", argv[0]);
        return SYS_ERR_OK;
    }

    err = SYS_ERR_OK;
    for(int i = 1; err_is_ok(err) && i < argc; i ++) {
        // TODO: support relative paths
        err = cat_file(argv[i]);
    }
    if (err_is_fail(err)) {
        printf("failed to cat file: %s\n", err_getstring(err));
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