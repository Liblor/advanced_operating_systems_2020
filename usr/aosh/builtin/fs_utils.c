#include <stdio.h>
#include <stdlib.h>
#include <errors/errno.h>
#include "echo.h"
#include "builtin.h"
#include "fs_utils.h"
#include "../aosh.h"
#include <fs/fs.h>
#include <fs/dirent.h>
#include <aos/nameserver.h>

#define FILE_SEP '/'

static bool fs_init = false;
static char *cwd;

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
        cwd = strdup("/sdcard");        // XXX: currently hardcoded
    }
    return err;
}

static inline bool is_rel_path(const char *path)
{
    return path[0] != FILE_SEP;
}

/**
 * Concats a path with a filename returns malloced memory
 * @param path Of the form "/haha/ho" or "/shout/out/to/bean/for/nice/buildin/api/"
 * @param filename Filename without starting /, e.g. "dude"
 * @return "/haha/ho/dude"
 */
static char *concat_path(const char *path, const char *filename)
{
    // sorry sightly ugly
    size_t len_path = strlen(path);
    size_t len_filename = strlen(filename);
    size_t n = len_path + len_filename + 1;
    if (path[len_path-1] != FILE_SEP) {
        n++;
    }
    char *ret = calloc(n, 1);
    if (ret == NULL) return ret;
    memcpy(ret, path, len_path);
    if (path[len_path-1] != FILE_SEP) {
        ret[len_path] = FILE_SEP;
        len_path++;
    }
    memcpy(ret + len_path, filename, len_filename);
    return ret;
}

/**
 * Executes `func(file)`. `file` gets extended to absolut path if necessary
 * @param func Func to execute
 * @param file Filename
 * @return
 */
static errval_t perform_with_path(
    errval_t (*func)(const char *),
    const char *file
) {
    errval_t err;
    if (is_rel_path(file)) {
        char *path = concat_path(cwd, file);
        if (path == NULL) { return LIB_ERR_MALLOC_FAIL; }
        err = func(path);
        free(path);
    } else {
        err = func(file);
    }
    return err;
}

static errval_t cat_file(const char *file)
{
    int res = 0;
    FILE *f = fopen(file, "r");
    if (f == NULL) {
        return FS_ERR_OPEN;
    }
    res = fseek(f , 0, SEEK_END);
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

errval_t builtin_cat(int argc, char **argv)
{
    errval_t err;
    err = ensure_init();
    if (err_is_fail(err)) {return err;}

    if(argc < 2) {
        printf("usage: %s [file...]\n", argv[0]);
        return SYS_ERR_OK;
    }

    err = SYS_ERR_OK;
    for(int i = 1; err_is_ok(err) && i < argc; i ++) {
        err = perform_with_path(cat_file, argv[i]);
    }
    if (err_is_fail(err)) {
        printf("failed to cat file: %s\n", err_getstring(err));
    }
    return SYS_ERR_OK;
}

static errval_t ls_dir(const char *dir)
{
    errval_t err;
    fs_dirhandle_t dh;
    err = opendir(dir, &dh);
    if (err_is_fail(err)) {
        return err;
    }
    assert(dh);
    //struct fs_fileinfo finfo;
    do {
        char *name;
        err = readdir(dh, &name);
        if (err_no(err) == FS_ERR_INDEX_BOUNDS) {
            break;
        } else if (err_is_fail(err)) {
            goto cleanup;
        }
        // TODO: color for dirs
        /*
        err = stat(name, &finfo);
        if (err_is_fail(err)) {
            return err;
        }
        if (finfo.type == FS_DIRECTORY) {
            printf("\033[34m");
        }
         */
        printf("%s\n", name);
        /*
        if (finfo.type == FS_DIRECTORY) {
            printf("\033[0m");
        }
         */
        free(name);
    } while(err_is_ok(err));

    return closedir(dh);
cleanup:
    closedir(dh);
    return err;
}

errval_t builtin_ls(int argc, char **argv)
{
    errval_t err;
    err = ensure_init();
    if (err_is_fail(err)) {return err;}

    if(argc < 2) {
        return ls_dir(cwd);
    }

    err = SYS_ERR_OK;
    for(int i = 1; i < argc; i ++) {
        if (argc > 2) {
            printf("%s:\n", argv[i]);
        }
        err = perform_with_path(ls_dir, argv[i]);
        if (err_is_fail(err)) {
            printf("failed to list folder: %s\n", err_getstring(err));
        }
    }
    return SYS_ERR_OK;
}

errval_t builtin_cd(int argc, char **argv)
{
    if(argc < 2) {
        printf("usage: %s path\n", argv[0]);
        return SYS_ERR_OK;
    }
    errval_t err;
    err = ensure_init();
    if (err_is_fail(err)) {
        return err;
    }
    fs_dirhandle_t dh;
    char *new_path;
    if (is_rel_path(argv[1])) {
        new_path = concat_path(cwd, argv[1]);
    } else {
        new_path = strdup(argv[1]);
    }
    if (new_path == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    err = opendir(new_path, &dh);
    if (err_is_fail(err)) {
        printf("failed to change directory: %s\n", err_getstring(err));
        closedir(dh);
        return err;
    }
    closedir(dh);
    free(cwd);
    cwd = new_path;
    return SYS_ERR_OK;
}

errval_t builtin_pwd(int argc, char **argv)
{
    errval_t err = ensure_init();
    if (err_is_fail(err)) {
        return err;
    }
    printf("%s\n", cwd);
    return SYS_ERR_OK;
}

errval_t builtin_mkdir(int argc, char **argv)
{
    errval_t err;
    err = ensure_init();
    if (err_is_fail(err)) {return err;}

    if(argc < 2) {
        printf("usage: %s [file...]\n", argv[0]);
        return SYS_ERR_OK;
    }

    err = SYS_ERR_OK;
    for(int i = 1; err_is_ok(err) && i < argc; i ++) {
        err = perform_with_path(mkdir, argv[i]);
    }
    if (err_is_fail(err)) {
        printf("failed to cat file: %s\n", err_getstring(err));
    }
    return SYS_ERR_OK;
}

errval_t builtin_rmdir(int argc, char **argv)
{
    errval_t err;
    err = ensure_init();
    if (err_is_fail(err)) {return err;}

    if(argc < 2) {
        printf("usage: %s [file...]\n", argv[0]);
        return SYS_ERR_OK;
    }

    err = SYS_ERR_OK;
    for(int i = 1; err_is_ok(err) && i < argc; i ++) {
        err = perform_with_path(rmdir, argv[i]);
    }
    if (err_is_fail(err)) {
        printf("failed to remove directory: %s\n", err_getstring(err));
    }
    return SYS_ERR_OK;
}

errval_t builtin_rm(int argc, char **argv)
{
    errval_t err;
    err = ensure_init();
    if (err_is_fail(err)) {return err;}

    if(argc < 2) {
        printf("usage: %s [file...]\n", argv[0]);
        return SYS_ERR_OK;
    }

    err = SYS_ERR_OK;
    for(int i = 1; err_is_ok(err) && i < argc; i ++) {
        err = perform_with_path(rm, argv[i]);
    }
    if (err_is_fail(err)) {
        printf("failed to rm file: %s\n", err_getstring(err));
    }
    return SYS_ERR_OK;
}

static errval_t touch(const char *name)
{
    FILE *f = fopen(name, "w");
    if (f == NULL) {
        printf("failed to touch file: %s\n", name);
        return FS_ERR_OPEN;
    }
    fclose(f);
    return SYS_ERR_OK;
}

errval_t builtin_touch(int argc, char **argv)
{
    errval_t err;
    err = ensure_init();
    if (err_is_fail(err)) {return err;}

    if(argc < 2) {
        printf("usage: %s [file...]\n", argv[0]);
        return SYS_ERR_OK;
    }

    err = SYS_ERR_OK;
    for(int i = 1; err_is_ok(err) && i < argc; i ++) {
        err = perform_with_path(touch, argv[i]);
    }
    return SYS_ERR_OK;
}