#include <errors/errno.h>
#include <aos/aos_rpc.h>
#include <fs/fat32.h>
#include <fs/fs.h>
#include <ctype.h>


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
    mnt->cluster_begin_lba = mnt->fat_lba + (mnt->number_of_fats * mnt->sector_per_fat);
    memset(&mnt->root, 0, sizeof(struct fat32_dirent));
    mnt->root.cluster = mnt->root_dir_first_cluster;
    mnt->root.dir_entry.first_cluster_lo = mnt->root_dir_first_cluster;
    mnt->root.dir_entry.attr |= 0b00010000;
    mnt->mount_point = name;
    if (mnt->mount_point[0] == FS_PATH_SEP) {
        mnt->mount_point++;
    }

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

static inline bool end_of_directory(struct dir_entry *dir_entry) {
    return dir_entry->shortname[0] == '\0';
}

static inline bool shortname_marked_unused(
    struct dir_entry *dir_entry
) {
    return dir_entry->shortname[0] == 0xe5;
}

static inline size_t shortname8_len(const char *shortname)
{
    size_t i;
    for (i = 0; i < 8; i++) {
        if (shortname[i] == 0x20) {
            break;
        }
    }
    return i;
}

static inline size_t shortname3_len(const char *shortname)
{
    size_t i;
    for (i = 8; i < 11; i++) {
        if (shortname[i] == 0x20) {
            break;
        }
    }
    return i-8;
}

/**
 * Helper function to compare a filename to 8.3 shortname
 * @param dir_entry Fat32 32 byte directory entry
 * @param cname Zero terminated string
 * @return
 */
static bool equal_shortname(
    struct dir_entry *dir_entry,
    void *cname
) {
    const char *shortname = dir_entry->shortname;
    const char *name = cname;
    if (strcmp(name, "..") == 0) {
        return shortname[0] == '.' && shortname[1] == '.';
    } else if (strcmp(name, ".") == 0) {
        return shortname[0] == '.';
    }
    size_t len_name8;
    size_t len_name3 = 0;
    size_t len_shortname8 = shortname8_len(shortname);
    size_t len_shortname3 = shortname3_len(shortname);
    char *dot = strchr(name, '.');
    if (dot == NULL) {
        len_name8 = strlen(name);
    } else {
        len_name8 = dot - name;
        dot++;
        len_name3 = strlen(dot);
    }
    if (len_name8 != len_shortname8) { return false; }
    if (len_name3 != len_shortname3) { return false; }
    if (strncasecmp(name, shortname, len_shortname8) != 0) { return false; }
    if (strncasecmp(dot, shortname+8, len_shortname3) != 0) { return false; }
    return true;
}

__unused static bool entry_is_used(
    struct dir_entry *dir_entry,
    void *ign
) {
    return (! shortname_marked_unused(dir_entry));
}

static bool entry_is_used_not_dot(
        struct dir_entry *dir_entry,
        void *ign
) {
    debug_printf("used? 0x%x\n", dir_entry->shortname[0]);
    return ((! shortname_marked_unused(dir_entry)) && dir_entry->shortname[0] != '.');
}

static void lower_string(char *str)
{
    for (; *str; ++str) *str = tolower(*str);
}

static errval_t shortname_to_name(
    const char* shortname,
    char **name
) {
    *name = calloc(1, 12);
    if (*name == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    size_t len8 = shortname8_len(shortname);
    size_t len3 = shortname3_len(shortname);
    memcpy(*name, shortname, len8);
    if (len3) {
        (*name)[len8] = '.';
        memcpy(*name + len8 + 1, shortname + 8, len3);
    }
    lower_string(*name);

    return SYS_ERR_OK;
}

static inline bool is_dir(struct dir_entry *dir_entry)
{
    return dir_entry->attr & 0b00010000;
}

static struct fat32_handle *handle_open(
    struct fat32_dirent *d,
    const char *path
) {
    struct fat32_handle *h = calloc(1, sizeof(struct fat32_handle));
    if (h == NULL) {
        return NULL;
    }
    h->isdir = is_dir(&d->dir_entry);
    memcpy(&h->dirent, d, sizeof(struct fat32_dirent));
    h->path = strdup(path);
    h->current_cluster = h->dirent.dir_entry.first_cluster_lo;
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

/**
 * Set `dirent` to first dirent that satisfies `comparator(dirent, comparator_arg1)`,
 * if no such entry can be found the last one in `root` is returned.
 */
static errval_t find_dirent(
    struct fat32_mnt *mnt,
    struct fat32_dirent *root,
    dir_comparator comparator,
    void *comparator_arg1,
    struct fat32_dirent *dirent
) {
    if (!is_dir(&root->dir_entry)) { return FS_ERR_NOTDIR; }

    errval_t err;
    uint32_t cluster_nr = root->dir_entry.first_cluster_lo;
    uint8_t buf[BLOCK_SIZE];
    struct dir_entry *d = (struct dir_entry *)&buf;

    do {
        uint32_t current_lba = cluster_to_lba(mnt, cluster_nr);
        err = aos_rpc_block_driver_read_block(
            aos_rpc_get_block_driver_channel(),
            current_lba,
            buf,
            BLOCK_SIZE
        );
        if (err_is_fail(err)) {
            return err;
        }
        assert(FAT32_ENTRIES_PER_BLOCK == 16);
        for (uint8_t i = 0; i < mnt->sectors_per_cluster; i++) {
            for (int j = 0; j < FAT32_ENTRIES_PER_BLOCK; j++) {
                if (end_of_directory(d + j)) {
                    dirent->dir_entry = d[j];
                    dirent->cluster = cluster_nr;
                    dirent->index = i * FAT32_ENTRIES_PER_BLOCK + j;
                    return FS_ERR_NOTFOUND;
                }
                if (comparator(d + j, comparator_arg1)) {
                    dirent->dir_entry = d[j];
                    dirent->cluster = cluster_nr;
                    dirent->index = i * FAT32_ENTRIES_PER_BLOCK + j;
                    return SYS_ERR_OK;
                }
            }
            err = aos_rpc_block_driver_read_block(
                    aos_rpc_get_block_driver_channel(),
                    current_lba + i,
                    buf,
                    BLOCK_SIZE
            );
            if (err_is_fail(err)) {
                return err;
            }
        }
        err = next_cluster(mnt, cluster_nr, &cluster_nr);
        if (err_is_fail(err)) {
            return err;
        }
    } while (cluster_nr < 0xfffffff8);

    return FS_ERR_NOTFOUND;
}

static void next_name_of_path(
    const char *path_pos,
    char **nextsep,
    size_t *nextlen
) {
    *nextsep = strchr(path_pos, FS_PATH_SEP);
    if (*nextsep == NULL) {
        *nextlen = strlen(path_pos);
    } else {
        *nextlen = *nextsep - path_pos;
    }
}

__unused static errval_t resolve_path(
    struct fat32_mnt *mnt,
    struct fat32_dirent *root,
    const char *path,
    struct fat32_handle **ret_fh
) {
    errval_t err;
    size_t pos = 0;
    struct fat32_dirent next_dirent;

    if (path[pos] == FS_PATH_SEP) {
        pos++;
    }
    // skip mount point
    if (root == &mnt->root) {
        char *nextsep;
        size_t nextlen;
        next_name_of_path(&path[pos], &nextsep, &nextlen);
        char pathbuf[nextlen + 1];
        memcpy(pathbuf, &path[pos], nextlen);
        pathbuf[nextlen] = '\0';
        if (strcmp(pathbuf, mnt->mount_point) != 0) {
            return FS_ERR_NOTFOUND;
        }
        pos += nextlen + 1;
    }

    if (path[pos] == FS_PATH_SEP) {
        pos++;
    }
    while (path[pos] != '\0') {
        char *nextsep;
        size_t nextlen;
        next_name_of_path(&path[pos], &nextsep, &nextlen);

        char pathbuf[nextlen + 1];
        memcpy(pathbuf, &path[pos], nextlen);
        pathbuf[nextlen] = '\0';

        err = find_dirent(mnt, root, &equal_shortname, pathbuf, &next_dirent);
        if (err_is_fail(err)) {
            return err;
        }
        if (next_dirent.dir_entry.first_cluster_lo == 0) {  // ".." special case
            next_dirent.dir_entry.first_cluster_lo = mnt->root_dir_first_cluster;
        }
        if (!is_dir(&next_dirent.dir_entry) && nextsep != NULL) {
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
    errval_t err;
    struct fat32_mnt *mnt = st;
    struct fat32_handle *handle;
    err = resolve_path(mnt, &mnt->root, path, &handle);
    if (err_is_fail(err)) {
        return err;
    }
    if (!handle->isdir) {
        handle_close(handle);
        return FS_ERR_NOTDIR;
    }
    *rethandle = handle;
    return SYS_ERR_OK;
}

static errval_t next_dir_entry(
    struct fat32_mnt *mnt,
    struct fat32_handle *h
) {
    h->dir_offset++;
    if (h->dir_offset < FAT32_ENTRIES_PER_BLOCK) {
        return SYS_ERR_OK;
    }
    // new sector
    h->dir_offset = 0;
    h->sector_rel_cluster++;
    if (h->sector_rel_cluster < mnt->sectors_per_cluster) {
        return SYS_ERR_OK;
    }
    // new cluster
    h->sector_rel_cluster = 0;
    errval_t err = next_cluster(mnt, h->current_cluster, &h->current_cluster);
    assert(h->current_cluster < 0xfffffff8);    // a end of directory entry should come first
    return err;
}

__unused errval_t fat32_dir_read_next(
    void *st,
    fat32_handle_t inhandle,
    char **retname,
    struct fs_fileinfo *info
) {
    errval_t err;
    struct fat32_mnt *mnt = st;
    struct fat32_handle *h = inhandle;

    if (!h->isdir) {
        return FS_ERR_NOTDIR;
    }
    uint8_t buf[BLOCK_SIZE];
    err = aos_rpc_block_driver_read_block(
        aos_rpc_get_block_driver_channel(),
        cluster_to_lba(mnt, h->current_cluster) + h->sector_rel_cluster,
        buf,
        BLOCK_SIZE
    );
    if (err_is_fail(err)) {
        return err;
    }
    struct dir_entry *dir_entry = ((struct dir_entry *)buf) + h->dir_offset;

    //while (dir_entry->shortname[0] == 0xe5) {
    while (shortname_marked_unused(dir_entry)) {
        uint32_t old_offset = h->dir_offset;
        err = next_dir_entry(mnt, h);
        if (err_is_fail(err)) {
            return err;
        }
        if (h->dir_offset < old_offset) {   // new sector
            err = aos_rpc_block_driver_read_block(
                aos_rpc_get_block_driver_channel(),
                cluster_to_lba(mnt, h->current_cluster) + h->sector_rel_cluster,
                buf,
                BLOCK_SIZE
            );
            if (err_is_fail(err)) {
                return err;
            }
        }
        dir_entry = ((struct dir_entry *)buf) + h->dir_offset;
    }
    if (end_of_directory(dir_entry)) {
        return FS_ERR_INDEX_BOUNDS;
    }
    if (retname != NULL) {
        err = shortname_to_name(dir_entry->shortname, retname);
        if (err_is_fail(err)) {
            return err;
        }
    }
    if (info != NULL) {
        info->type = is_dir(dir_entry) ? FS_DIRECTORY : FS_FILE;
        info->size = dir_entry->size;
    }

    return next_dir_entry(mnt, h);
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

__unused errval_t fat32_open(void *st, const char *path, fat32_handle_t *rethandle)
{
    errval_t err;
    struct fat32_mnt *mnt = st;

    struct fat32_handle *handle;
    err = resolve_path(mnt, &mnt->root, path, &handle);
    if (err_is_fail(err)) {
        return err;
    }

    if (handle->isdir) {
        handle_close(handle);
        return FS_ERR_NOTFILE;
    }

    *rethandle = handle;
    return SYS_ERR_OK;
}

__unused errval_t fat32_close(void *st, fat32_handle_t inhandle)
{
    struct fat32_handle *handle = inhandle;
    if (handle->isdir) {
        return FS_ERR_NOTFILE;
    }
    handle_close(handle);
    return SYS_ERR_OK;
}

__unused errval_t fat32_tell(void *st, fat32_handle_t handle, size_t *pos)
{
    struct fat32_handle *h = handle;
    if (h->isdir) {
        *pos = 0;
    } else {
        *pos = h->file_pos;
    }
    return SYS_ERR_OK;
}

__unused errval_t fat32_stat(void *st, fat32_handle_t inhandle, struct fs_fileinfo *info)
{
    struct fat32_handle *h = inhandle;
    assert(info != NULL);
    info->type = h->isdir ? FS_DIRECTORY : FS_FILE;
    info->size = h->dirent.dir_entry.size;
    return SYS_ERR_OK;
}

errval_t fat32_read(
    void *st,
    fat32_handle_t handle,
    void *buffer,
    size_t bytes,
    size_t *bytes_read
) {
    errval_t err;
    struct fat32_mnt *mnt = st;
    struct fat32_handle *h = handle;

    if (h->isdir) {
        return FS_ERR_NOTFILE;
    }

    *bytes_read = 0;

    if (h->dirent.dir_entry.size < h->file_pos) {
        bytes = 0;
    } else if (h->dirent.dir_entry.size < h->file_pos + bytes) {
        bytes = h->dirent.dir_entry.size - h->file_pos;
        assert(h->file_pos + bytes == h->dirent.dir_entry.size);
    }

    uint8_t buf[BLOCK_SIZE];
    while (*bytes_read < bytes) {
        err = aos_rpc_block_driver_read_block(
            aos_rpc_get_block_driver_channel(),
            cluster_to_lba(mnt, h->current_cluster) + h->sector_rel_cluster,
            buf,
            BLOCK_SIZE
        );
        if (err_is_fail(err)) {
            return err;
        }
        uint32_t from = h->file_pos % BLOCK_SIZE;
        uint32_t size = MIN(BLOCK_SIZE - from, bytes - *bytes_read);
        //size = MIN(size, h->dirent.dir_entry.size - h->file_pos);
        memcpy(buffer + *bytes_read, &buf[from], size);
        uint32_t new_sector = (h->file_pos + size)/BLOCK_SIZE - h->file_pos/BLOCK_SIZE;
        *bytes_read += size;
        h->file_pos += size;
        h->sector_rel_cluster += new_sector;
        if (h->sector_rel_cluster >= mnt->sectors_per_cluster) {
            // new cluster
            h->sector_rel_cluster = 0;
            err = next_cluster(mnt, h->current_cluster, &h->current_cluster);
            if (err_is_fail(err)) {
                return err;
            }
            assert(h->current_cluster < 0xfffffff8);    // a end of directory entry should come first
        }
    }

    assert(*bytes_read == bytes);
    return SYS_ERR_OK;
}

static errval_t file_seek_pos(
    struct fat32_mnt *mnt,
    struct fat32_handle *h,
    uint32_t new_pos
) {
    uint32_t pos = MIN(new_pos, h->dirent.dir_entry.size);
    uint32_t number_of_cluster_to_pos = pos / (BLOCK_SIZE * mnt->sectors_per_cluster);
    uint32_t curr_cluster_count = h->file_pos / (BLOCK_SIZE * mnt->sectors_per_cluster);
    uint32_t curr_cluster = h->current_cluster;
    h->file_pos = new_pos;
    if (curr_cluster_count > number_of_cluster_to_pos) {
        curr_cluster_count = 0;
        curr_cluster = h->dirent.dir_entry.first_cluster_lo;
    }

    while (curr_cluster_count < number_of_cluster_to_pos) {
        errval_t err = next_cluster(mnt, curr_cluster, &curr_cluster);
        if (err_is_fail(err)) {
            return err;
        }
        assert(curr_cluster < 0xfffffff8);
        curr_cluster_count++;
    }

    h->current_cluster = curr_cluster;
    h->sector_rel_cluster = (new_pos % (BLOCK_SIZE * mnt->sectors_per_cluster)) / BLOCK_SIZE;
    return SYS_ERR_OK;
}

errval_t fat32_seek(
    void *st,
    fat32_handle_t handle,
    enum fs_seekpos whence,
    off_t offset
) {
    struct fat32_mnt *mnt = st;
    struct fat32_handle *h = handle;
    errval_t err = SYS_ERR_OK;

    switch (whence) {
        case FS_SEEK_SET:
            assert(offset >= 0);
            if (h->isdir) {
                assert(!"NYI");
            } else {
                err = file_seek_pos(mnt, h, offset);
            }
            break;
        case FS_SEEK_CUR:
            if (h->isdir) {
                assert(!"NYI");
            } else {
                assert(offset >= 0 || -offset <= (int32_t)h->file_pos);
                err = file_seek_pos(mnt, h, (int32_t )h->file_pos + (int32_t)offset);
            }

            break;
        case FS_SEEK_END:
            if (h->isdir) {
                assert(!"NYI");
            } else {
                assert(offset >= 0 || -offset <= (int32_t )h->dirent.dir_entry.size);
                err = file_seek_pos(mnt, h, (int32_t )h->dirent.dir_entry.size + (int32_t)offset);
            }
            break;
        default:
            USER_PANIC("invalid whence argument to fat32fs seek");
    }
    return err;
}

/**
 * Check if directory directory handler is empty
 * @param mnt Fat32 mount
 * @param h Handler to directory that is checked if it is empty
 * @return SYS_ERR_OK if empty, FS_ERR_NOTEMPTY if not empty, or some error if call failed
 */
static errval_t is_dir_empty(
    struct fat32_mnt *mnt,
    struct fat32_handle *h
) {
    errval_t err;
    struct fat32_dirent dirent;
    err = find_dirent(mnt, &h->dirent, entry_is_used_not_dot, NULL, &dirent);
    if (err == SYS_ERR_OK) {
        return FS_ERR_NOTEMPTY;
    } else if (err == FS_ERR_NOTFOUND){
        return SYS_ERR_OK;
    } else {
        return err;
    }
}

__unused static errval_t clean_fat_chain(
    struct fat32_mnt *mnt,
    uint32_t cluster_start
) {
    errval_t err;
    uint32_t fat_cutout[BLOCK_SIZE / sizeof(uint32_t)];
    uint32_t cluster_nr = cluster_start;

    uint32_t index = mnt->fat_lba + cluster_nr / 128;
    uint32_t prev_index = index - 1;
    while (cluster_nr < 0xfffffff8) {
        if (prev_index != index) {
            err = aos_rpc_block_driver_read_block(
                aos_rpc_get_block_driver_channel(),
                index,
                (uint8_t *)fat_cutout,
                BLOCK_SIZE
            );
            if (err_is_fail(err)) {
                return err;
            }
        }
        uint32_t prev_cluster_nr = cluster_nr;
        cluster_nr = fat_cutout[prev_cluster_nr % 128];
        fat_cutout[prev_cluster_nr % 128] = 0;
        prev_index = index;
        index = mnt->fat_lba + cluster_nr / 128;
        if (prev_index != index || cluster_nr >= 0xfffffff8) {
            err = aos_rpc_block_driver_write_block(
                aos_rpc_get_block_driver_channel(),
                index,
                (uint8_t *)fat_cutout,
                BLOCK_SIZE
            );
            if (err_is_fail(err)) {
                return err;
            }
        }
    }
    return SYS_ERR_OK;
}

/**
 * Write back dir_entry of handle
 */
static errval_t update_dir_entry_on_disk(
    struct fat32_mnt *mnt,
    struct fat32_handle *h
) {
    errval_t err;
    uint8_t *buf[BLOCK_SIZE];
    uint32_t index = cluster_to_lba(mnt, h->dirent.cluster);
    index += h->dirent.index / FAT32_ENTRIES_PER_BLOCK;     // get section
    uint32_t offset = h->dirent.index % FAT32_ENTRIES_PER_BLOCK;
    err = aos_rpc_block_driver_read_block(
        aos_rpc_get_block_driver_channel(),
        index,
        buf,
        BLOCK_SIZE
    );
    if (err_is_fail(err)) {
        return err;
    }
    struct dir_entry *dir_entry = (struct dir_entry *)buf;
    dir_entry[offset] = h->dirent.dir_entry;
    return aos_rpc_block_driver_write_block(
        aos_rpc_get_block_driver_channel(),
        index,
        buf,
        BLOCK_SIZE
    );
}

__unused errval_t fat32_rmdir(
        void *st,
        const char *path
) {
    errval_t err;
    struct fat32_mnt *mnt = st;
    struct fat32_handle *handle;
    err = resolve_path(mnt, &mnt->root, path, &handle);
    if (err_is_fail(err)) {
        return err;
    }
    if (!handle->isdir) {
        err = FS_ERR_NOTDIR;
        goto cleanup;
    }

    // TODO: Check if directory is not open (FS_ERR_BUSY)

    err = is_dir_empty(mnt, handle);
    if (err_is_fail(err)) {
        goto cleanup;
    }
    err = clean_fat_chain(mnt, handle->dirent.dir_entry.first_cluster_lo);
    if (err_is_fail(err)) {
        goto cleanup;
    }
    handle->dirent.dir_entry.shortname[0] = 0xe5;   // unused
    err = update_dir_entry_on_disk(mnt, handle);
cleanup:
    handle_close(handle);
    return err;
}
