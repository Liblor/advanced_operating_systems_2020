#include <errors/errno.h>
#include <aos/aos_rpc.h>
#include <fs/fat32.h>
#include <fs/fs.h>


static inline uint32_t cluster_to_lba(struct fat32_mnt *mnt, uint32_t cluster_num)
{
    return mnt->cluster_begin_lba + (cluster_num - 2) * mnt->sectors_per_cluster;
}

errval_t mount_fat32(const char *name, struct fat32_mnt **fat_mnt)
{
    errval_t err;
    uint8_t block[BLOCK_SIZE];
    err = aos_rpc_block_driver_read_block(
        aos_rpc_get_block_driver_channel(),
        0,
        block,
        BLOCK_SIZE
    );
    debug_printf("first 0x%x\n", block[0]);
    if (err_is_fail(err)) {
        return err;
    }
    assert(block[511] == 0xAA);
    assert(block[510] == 0x55);
    *fat_mnt = malloc(sizeof(struct fat32_mnt));
    if (*fat_mnt == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    struct fat32_mnt *mnt = *fat_mnt;

    if (*(uint16_t *)(block + BPB_BytsPerSec) != BLOCK_SIZE) {
        debug_printf("Only 512 bytes per sector supported (found %u)\n",
                *(uint16_t *)(block + BPB_BytsPerSec));
        return LIB_ERR_NOT_IMPLEMENTED;
    }

    mnt->reserved_sector_count = *(uint16_t *)(block + BPB_RsvdSecCnt);
    mnt->sector_per_fat = *(uint32_t *)(block + BPB_FATSz32);
    mnt->sectors_per_cluster = *(uint8_t *)(block + BPB_SecPerClus);
    mnt->root_dir_first_cluster = *(uint32_t *)(block + BPB_RootClus);
    mnt->number_of_fats = *(uint8_t *)(block + BPB_NumFATs);
    // XXX: No partition support, i.e. 0 stands for partition offset
    mnt->fat_lba = 0 + mnt->reserved_sector_count;
    mnt->cluster_begin_lba = mnt->fat_lba + mnt->reserved_sector_count + (mnt->number_of_fats * mnt->sector_per_fat);

#if 0
    debug_printf("reserved_sector_count 0x%x\n", mnt->reserved_sector_count);
    debug_printf("sector_per_fat 0x%x\n", mnt->sector_per_fat);
    debug_printf("sector_per_clustor 0x%x\n", mnt->sectors_per_cluster);
    debug_printf("root_dir_first_cluster 0x%x\n", mnt->root_dir_first_cluster);
    debug_printf("number_of_fats 0x%x\n", mnt->number_of_fats);
    debug_printf("cluster_begin_lba 0x%x\n", mnt->cluster_begin_lba);
#endif

    return SYS_ERR_OK;
}

static inline bool is_dir(struct fat32_dirent *dirent)
{
    return dirent->dir_entry.attr & 0b00010000;
}


static struct fat32_handle *handle_open(
    struct fat32_dirent *d,
    const char *path
) {
    struct fat32_handle *h = calloc(1, sizeof(struct fat32_handle));
    if (h == NULL) {
        return NULL;
    }
    h->isdir = is_dir(d);
    memcpy(&h->dirent, d, sizeof(struct fat32_dirent));
    h->path = strdup(path);
    return h;
}

static inline void handle_close(struct fat32_handle *h)
{
    assert(h->path != NULL);
    free(h->path);
    free(h);
}

static inline errval_t next_cluster(
        struct fat32_mnt *mnt,
        uint32_t cluster_nr,
        uint32_t *ret_cluster_nr
) {
    errval_t err;
    uint8_t buf[BLOCK_SIZE];
    uint32_t index = mnt->fat_lba + cluster_nr / 128;
    err = aos_rpc_block_driver_read_block(
            aos_rpc_get_block_driver_channel(),
            index,
            buf,
            BLOCK_SIZE
    );
    if (err_is_fail(err)) {
        return err;
    }

    *ret_cluster_nr = *((uint32_t *)buf + cluster_nr % 128);
    return SYS_ERR_OK;
}

static errval_t find_dirent(
    struct fat32_mnt *mnt,
    struct fat32_dirent *root,
    const char *name,
    struct fat32_dirent *dirent
) {
    if (!is_dir(root)) { return FS_ERR_NOTDIR; }

    errval_t err;
    uint32_t cluster_nr = root->cluster;
    uint8_t buf[BLOCK_SIZE];
    struct dir_entry *d = (struct dir_entry *)&buf;

    do {
        err = aos_rpc_block_driver_read_block(
                aos_rpc_get_block_driver_channel(),
                cluster_to_lba(mnt, cluster_nr),
                buf,
                BLOCK_SIZE
        );
        if (err_is_fail(err)) {
            return err;
        }
        for (int i = 0; i < 16; i++) {
            if (d[i].shortname[0] == '\0') { break; }
            else if (d[i].shortname[0] == 0xe5) { continue; }   // 0xe5 == unused
            if (strcmp(d[i].shortname, name) == 0) {
                dirent->dir_entry = d[i];
                dirent->cluster = cluster_nr;
                dirent->offset = i;
                return SYS_ERR_OK;
            }
        }
        err = next_cluster(mnt, cluster_nr, &cluster_nr);
        if (err_is_fail(err)) {
            return err;
        }
    } while (cluster_nr < 0xfffffff8);

    return FS_ERR_NOTFOUND;
}

__unused static errval_t resolve_path(
    struct fat32_mnt *mnt,
    struct fat32_dirent *root,
    const char *path,
    struct fat32_handle **ret_fh
) {
    errval_t err;
    struct fat32_dirent next_dirent;

    // skip leading /
    size_t pos = 0;
    if (path[0] == FS_PATH_SEP) {
        pos++;
    }
    while (path[pos] != '\0') {
        char *nextsep = strchr(&path[pos], FS_PATH_SEP);
        size_t nextlen;
        if (nextsep == NULL) {
            nextlen = strlen(&path[pos]);
        } else {
            nextlen = nextsep - &path[pos];
        }

        char pathbuf[nextlen + 1];
        memcpy(pathbuf, &path[pos], nextlen);
        pathbuf[nextlen] = '\0';

        err = find_dirent(mnt, root, pathbuf, &next_dirent);
        if (err_is_fail(err)) {
            return err;
        }
        if (!is_dir(&next_dirent) && nextsep != NULL) {
            return FS_ERR_NOTDIR;
        }
        root = &next_dirent;
        if (nextsep == NULL) {
            break;
        }
        pos += nextlen + 1;
    }

    /* create the handle */
    if (ret_fh) {
        struct fat32_handle *fh = handle_open(root, path);
        if (fh == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        *ret_fh = fh;
    }
    return SYS_ERR_OK;
}


__unused errval_t fat32_opendir(
    void *st,
    const char *path,
    fat32_handle_t *rethandle)
{
    /*
    errval_t err;
    struct fat32_mnt *mount = st;
    struct fat32_handle *handle;
    err = resolve_path(mount->root, path, &handle);
    if (err_is_fail(err)) {
        return err;
    }

    if (!handle->isdir) {
        handle_close(handle);
        return FS_ERR_NOTDIR;
    }

    handle->dir_pos = handle->dirent->dir;

    *rethandle = handle;
     */

    return LIB_ERR_NOT_IMPLEMENTED;
}

__unused errval_t fat32_dir_read_next(
    void *st,
    fat32_handle_t inhandle,
    char **retname,
    struct fs_fileinfo *info
) {
    return LIB_ERR_NOT_IMPLEMENTED;
}

__unused errval_t fat32_closedir(
    void *st,
    fat32_handle_t dhandle
) {
    struct fat32_handle *handle = dhandle;
    if (!handle->isdir) {
        return FS_ERR_NOTDIR;
    }
    free(handle->path);
    free(handle);
    return SYS_ERR_OK;
}
