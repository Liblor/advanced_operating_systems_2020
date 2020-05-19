#include <errors/errno.h>
#include <aos/aos_rpc.h>
#include <aos/fat32.h>


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

errval_t fat32_opendir(
    void *st,
    const char *path,
    fat32_handle_t *rethandle)
{
    errval_t err;
    struct fat32_mnt *mount = st;
    struct fat32_handle *handle;
    /*
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

errval_t fat32_dir_read_next(
    void *st,
    fat32_handle_t inhandle,
    char **retname,
    struct fs_fileinfo *info
) {
    return LIB_ERR_NOT_IMPLEMENTED;
}

errval_t fat32_closedir(
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
