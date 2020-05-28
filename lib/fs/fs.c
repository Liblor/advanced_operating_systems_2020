/**
 * \file fs.c
 * \brief Filesystem support library
 */

#include <aos/aos.h>


#include <fs/fs.h>
#include <fs/fat32.h>
#include <fs/dirent.h>
#include <fs/ramfs.h>
#include <aos/aos_rpc.h>

#include "fs_internal.h"

/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

/**
 * @brief initializes the filesystem library
 *
 * @return SYS_ERR_OK on success
 *         errval on failure
 *
 * NOTE: This has to be called before any access to the files
 */
errval_t filesystem_init(void)
{
#if 0
    errval_t err;
    ramfs_mount_t st = NULL;
    err = ramfs_mount("/", &st);
    if (err_is_fail(err)) {
        return err;
    }
#endif

    /* register libc fopen/fread and friends */
    struct aos_rpc *rpc = aos_rpc_get_filesystemserver_channel();
    if (rpc == NULL) {
        return AOS_ERR_FS_NOT_STARTED;
    }
    fs_libc_init(rpc);

    return SYS_ERR_OK;
}

/**
 * @brief mounts the URI at a give path
 *
 * @param path  path to mount the URI
 * @param uri   uri to mount
 *
 * @return SYS_ERR_OK on success
 *         errval on error
 *
 * This mounts the uri at a given, existing path.
 *
 * path: service-name://fstype/params
 */
errval_t filesystem_mount(const char *path, const char *uri)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}
