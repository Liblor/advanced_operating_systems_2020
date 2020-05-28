#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#include <errors/errno.h>
#include <aos/aos_rpc.h>
#include <fs/fat32.h>
#include <fs/fs.h>
#include <ctype.h>

static inline uint32_t cluster_to_lba(struct fat32_mnt *mnt, uint32_t cluster_num)
{
    return mnt->cluster_begin_lba + (cluster_num - 2) * mnt->sectors_per_cluster;
}

static inline uint32_t get_first_cluster_nr(struct dir_entry *d) {
    return ((uint32_t)d->first_cluster_hi << 16) | (uint32_t)d->first_cluster_lo;
}

static inline void set_first_cluster_nr(struct dir_entry *d, uint32_t first_cluster) {
    d->first_cluster_lo = 0xffff & first_cluster;
    d->first_cluster_hi = (uint16_t)(first_cluster >> 16);
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
    mnt->sectors_per_fat = *(uint32_t *)(block + BPB_FATSz32);
    mnt->sectors_per_cluster = *(uint8_t *)(block + BPB_SecPerClus);
    mnt->root_dir_first_cluster = *(uint32_t *)(block + BPB_RootClus);
    mnt->number_of_fats = *(uint8_t *)(block + BPB_NumFATs);
    // XXX: No partition support, i.e. 0 stands for partition offset
    mnt->fat_lba = 0 + mnt->reserved_sector_count;
    mnt->cluster_begin_lba = mnt->fat_lba + (mnt->number_of_fats * mnt->sectors_per_fat);
    memset(&mnt->root, 0, sizeof(struct fat32_dirent));
    mnt->root.cluster = mnt->root_dir_first_cluster;
    mnt->root.dir_entry.first_cluster_lo = 0xffff & mnt->root_dir_first_cluster;
    mnt->root.dir_entry.first_cluster_hi = mnt->root_dir_first_cluster >> 16;
    mnt->root.dir_entry.attr |= 0b00010000;
    mnt->mount_point = name;
    if (mnt->mount_point[0] == FS_PATH_SEP) {
        mnt->mount_point++;
    }
    mnt->next_free = 2;     // TODO: read value from FSI

#if 0
    debug_printf("reserved_sector_count 0x%x\n", mnt->reserved_sector_count);
    debug_printf("sectors_per_fat 0x%x\n", mnt->sectors_per_fat);
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

static inline bool is_shortname(
    struct dir_entry *dir_entry
) {
    return ('A' <= dir_entry->shortname[0] && dir_entry->shortname[0] <= 'Z') || dir_entry->shortname[0] == '.';
}

static inline bool isalphanum_str(const char *str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (! isalnum(str[i])) { return false; }
    }
    return true;
}

static bool is_valid_name_for_shortname(
    const char *name
) {
    size_t name_len = strnlen(name, 13);
    if (name_len > 12) { return false; }
    if (name_len == 0) { return false; }
    if (name[0] == '.') { return false; }
    if (isdigit(name[0])) { return false; }
    char *dot = strrchr(name, '.');
    if (dot == NULL) {
        if (name_len > 8) { return false; }
        if (! isalphanum_str(name, name_len)) { return false; }
    } else {
        size_t len8 = dot - name;
        dot++;
        size_t len3 = strnlen(dot, 5);
        if (len8 > 8) { return false; }
        if (len3 > 3) { return false; }
        if (! isalphanum_str(name, len8)) { return false; }
        if (! isalphanum_str(dot, len3)) { return false; }
    }
    return true;
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

static bool entry_is_unused(
        struct dir_entry *dir_entry,
        void *ign
) {
    return shortname_marked_unused(dir_entry);
}

static bool entry_is_used_not_dot(
        struct dir_entry *dir_entry,
        void *ign
) {
    return ((! shortname_marked_unused(dir_entry)) && dir_entry->shortname[0] != '.');
}

static void lower_string(char *str)
{
    for (; *str; ++str) *str = tolower(*str);
}

static errval_t shortname_to_name(
    const char *shortname,
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

/**
 * Convert a name to a 8.3 shortname
 * @param name Name that fits into a 8.3 shortname
 * @param shortname Buffer of at least 11 bytes, where the shortname is written to
 */
static void name_to_shortname(
    const char *name,
    char *shortname
) {
    uint32_t len_name8;
    uint32_t len_name3;
    memset(shortname, ' ', 11);
    char *dot = strchr(name, '.');
    if (dot) {
        len_name8 = dot - name;
        dot++;  // skip dot
        len_name3 = strnlen(dot, 3);
    } else {
        len_name8 = strnlen(name, 8);
        len_name3 = 0;
    }
    for (int i = 0; i < len_name8; i++) {
        shortname[i] = toupper(name[i]);
    }
    for (int i = 0; i < len_name3; i++) {
        shortname[8+i] = toupper(dot[i]);
    }
}

static inline bool is_dir(struct dir_entry *dir_entry)
{
    return dir_entry->attr & 0b00010000;
}

static inline void set_dir(struct dir_entry *dir_entry)
{
    dir_entry->attr |= 0b00010000;
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
    h->current_cluster = get_first_cluster_nr(&h->dirent.dir_entry);
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
    uint32_t index = mnt->fat_lba + cluster_nr / FAT32_FatEntriesPerSector;
    err = aos_rpc_block_driver_read_block(
        aos_rpc_get_block_driver_channel(),
        index,
        buf,
        BLOCK_SIZE
    );
    if (err_is_fail(err)) {
        return err;
    }

    *ret_cluster_nr = *((uint32_t *)buf + cluster_nr % FAT32_FatEntriesPerSector);
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
    uint32_t cluster_nr = get_first_cluster_nr(&root->dir_entry);
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
        assert(FAT32_DirEntriesPerBlock == 16);
        for (uint8_t i = 0; i < mnt->sectors_per_cluster; i++) {
            for (int j = 0; j < FAT32_DirEntriesPerBlock; j++) {
                if (end_of_directory(d + j)) {
                    if (dirent) {
                        dirent->dir_entry = d[j];
                        dirent->cluster = cluster_nr;
                        dirent->index = i * FAT32_DirEntriesPerBlock + j;
                    }
                    return FS_ERR_NOTFOUND;
                }
                if (comparator(d + j, comparator_arg1)) {
                    if (dirent) {
                        dirent->dir_entry = d[j];
                        dirent->cluster = cluster_nr;
                        dirent->index = i * FAT32_DirEntriesPerBlock + j;
                    }
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
    } while (cluster_nr < FAT32_EndCluster);

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

static errval_t resolve_path(
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
        pos += nextlen;
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
        if (get_first_cluster_nr(&next_dirent.dir_entry) == 0) {  // ".." special case
            set_first_cluster_nr(&next_dirent.dir_entry, mnt->root_dir_first_cluster);
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

errval_t fat32_opendir(
    void *st,
    const char *path,
    fat32_handle_t *rethandle
) {
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
    if (h->dir_offset < FAT32_DirEntriesPerBlock) {
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
    //assert(h->current_cluster < FAT32_EndCluster);    // a end of directory entry should come first
    return err;
}

errval_t fat32_dir_read_next(
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

    while (!is_shortname(dir_entry)) {
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
        if (end_of_directory(dir_entry)) {
            return FS_ERR_INDEX_BOUNDS;
        }
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

errval_t fat32_open(void *st, const char *path, fat32_handle_t *rethandle)
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

errval_t fat32_close(void *st, fat32_handle_t inhandle)
{
    struct fat32_handle *handle = inhandle;
    if (handle->isdir) {
        return FS_ERR_NOTFILE;
    }
    handle_close(handle);
    return SYS_ERR_OK;
}

errval_t fat32_tell(void *st, fat32_handle_t handle, size_t *pos)
{
    struct fat32_handle *h = handle;
    if (h->isdir) {
        *pos = 0;
    } else {
        *pos = h->file_pos;
    }
    return SYS_ERR_OK;
}

errval_t fat32_stat(void *st, fat32_handle_t inhandle, struct fs_fileinfo *info)
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

    size_t b_read = 0;

    if (h->dirent.dir_entry.size < h->file_pos) {
        bytes = 0;
    } else if (h->dirent.dir_entry.size < h->file_pos + bytes) {
        bytes = h->dirent.dir_entry.size - h->file_pos;
        assert(h->file_pos + bytes == h->dirent.dir_entry.size);
    }

    uint8_t buf[BLOCK_SIZE];
    while (b_read < bytes) {
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
        uint32_t size = MIN(BLOCK_SIZE - from, bytes - b_read);
        //size = MIN(size, h->dirent.dir_entry.size - h->file_pos);
        memcpy(buffer + b_read, &buf[from], size);
        uint32_t new_sector = (h->file_pos + size)/BLOCK_SIZE - h->file_pos/BLOCK_SIZE;
        b_read += size;
        h->file_pos += size;
        h->sector_rel_cluster += new_sector;
        if (h->sector_rel_cluster >= mnt->sectors_per_cluster) {
            assert(h->current_cluster < FAT32_EndCluster);
            // new cluster
            h->sector_rel_cluster = 0;
            err = next_cluster(mnt, h->current_cluster, &h->current_cluster);
            if (err_is_fail(err)) {
                return err;
            }
        }
    }

    if (bytes_read) {
        *bytes_read = b_read;
    }
    assert(b_read == bytes);
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
        curr_cluster = get_first_cluster_nr(&h->dirent.dir_entry);
    }

    while (curr_cluster_count < number_of_cluster_to_pos) {
        assert(curr_cluster < FAT32_EndCluster);
        // Could be optimized by not rereading if cluster is in same FAT block
        errval_t err = next_cluster(mnt, curr_cluster, &curr_cluster);
        if (err_is_fail(err)) {
            return err;
        }
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

static errval_t write_fatcutout(
        struct fat32_mnt *mnt,
        void *fat_cutout,
        uint32_t index
) {
    errval_t err;
    for (int i = 0; i < mnt->number_of_fats; i++) {
        err = aos_rpc_block_driver_write_block(
            aos_rpc_get_block_driver_channel(),
            index + i * mnt->sectors_per_fat,
            fat_cutout,
            BLOCK_SIZE
        );
        if (err_is_fail(err)) {
            return err;
        }
    }
    return SYS_ERR_OK;
}


// TODO: update mnt->nxt_free
static errval_t clean_fat_chain(
    struct fat32_mnt *mnt,
    uint32_t cluster_start
) {
    errval_t err;
    uint32_t fat_cutout[BLOCK_SIZE / sizeof(uint32_t)];
    uint32_t cluster_nr = cluster_start;

    uint32_t index = mnt->fat_lba + cluster_nr / FAT32_FatEntriesPerSector;
    uint32_t prev_index = index - 1;
    while (cluster_nr < FAT32_EndCluster) {
        // Only read when new block is accessed
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
        cluster_nr = fat_cutout[prev_cluster_nr % FAT32_FatEntriesPerSector];
        fat_cutout[prev_cluster_nr % FAT32_FatEntriesPerSector] = 0;
        prev_index = index;
        index = mnt->fat_lba + cluster_nr / FAT32_FatEntriesPerSector;
        if (prev_index != index || cluster_nr >= FAT32_EndCluster) {
            err = write_fatcutout(mnt, fat_cutout, prev_index);
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
    struct fat32_dirent *dirent
) {
    errval_t err;
    uint8_t *buf[BLOCK_SIZE];
    uint32_t index = cluster_to_lba(mnt, dirent->cluster);
    index += dirent->index / FAT32_DirEntriesPerBlock;     // get section
    uint32_t offset = dirent->index % FAT32_DirEntriesPerBlock;
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
    dir_entry[offset] = dirent->dir_entry;
    return aos_rpc_block_driver_write_block(
        aos_rpc_get_block_driver_channel(),
        index,
        buf,
        BLOCK_SIZE
    );
}

errval_t fat32_rmdir(
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
    err = clean_fat_chain(mnt, get_first_cluster_nr(&handle->dirent.dir_entry));
    if (err_is_fail(err)) {
        goto cleanup;
    }
    handle->dirent.dir_entry.shortname[0] = 0xe5;   // unused
    err = update_dir_entry_on_disk(mnt, &handle->dirent);
cleanup:
    handle_close(handle);
    return err;
}

errval_t fat32_remove(void *st, const char *path)
{
    errval_t err;
    struct fat32_mnt *mnt = st;
    struct fat32_handle *handle;
    err = resolve_path(mnt, &mnt->root, path, &handle);
    if (err_is_fail(err)) {
        return err;
    }
    if (handle->isdir) {
        err = FS_ERR_NOTFILE;
        goto cleanup;
    }
    // TODO: Check if file is not open (FS_ERR_BUSY)
    err = clean_fat_chain(mnt, get_first_cluster_nr(&handle->dirent.dir_entry));
    if (err_is_fail(err)) {
        goto cleanup;
    }
    handle->dirent.dir_entry.shortname[0] = 0xe5;   // unused
    err = update_dir_entry_on_disk(mnt, &handle->dirent);
cleanup:
    handle_close(handle);
    return err;
}

/**
 * Returns true iff fat entry is marked as free
 * @param fat_entry Fat entry
 * @return true iff fat entry is marked free
 */
static bool fat_is_free_cluster(uint32_t fat_entry)
{
    return !(fat_entry & 0x0fffffff);
}

static errval_t zero_out_cluster(struct fat32_mnt *mnt, uint32_t cluster_nr) {
    errval_t err;
    uint8_t buf[BLOCK_SIZE];
    memset(buf, 0, BLOCK_SIZE);
    for (uint32_t i = 0; i < mnt->sectors_per_cluster; i++) {
        err =  aos_rpc_block_driver_write_block(
            aos_rpc_get_block_driver_channel(),
            cluster_to_lba(mnt, cluster_nr) + i,
            buf,
            BLOCK_SIZE
        );
        if (err_is_fail(err)) {
            return err;
        }
    }
    return SYS_ERR_OK;
}

/**
 * Allocate `number_of_cluster` many clusters in the FAT
 * @param mnt
 * @param number_of_clusters How many clusters should be allocated
 * @param zero_out Whether clusters should be zeroed
 * @param ret_nr_allocated How many clusters could be allocated
 * @param ret_first_cluster_nr Cluster nr to first cluster of cluster chain
 * @return Error
 */
static errval_t allocate_clusters(
    struct fat32_mnt *mnt,
    uint32_t number_of_clusters,
    bool zero_out,
    uint32_t *ret_nr_allocated,
    uint32_t *ret_first_cluster_nr
) {
    errval_t err;
    uint32_t last_allocated_cluster_nr = FAT32_EndCluster;
    uint32_t counter = 0;
    uint32_t start_sector = mnt->next_free / FAT32_FatEntriesPerSector;     // relative to FAT
    uint32_t current_sector = start_sector;
    uint32_t fat_cutout[FAT32_FatEntriesPerSector];

    do {
        err = aos_rpc_block_driver_read_block(
            aos_rpc_get_block_driver_channel(),
            mnt->fat_lba + current_sector,
            fat_cutout,
            BLOCK_SIZE
        );
        if (err_is_fail(err)) {
            return err;
        }
        for (
            int i = (current_sector != 0 ? 0 : 2);      // first two entries are reserved!
            i < FAT32_FatEntriesPerSector && counter < number_of_clusters;
            i++
        ) {
            if (! fat_is_free_cluster(fat_cutout[i])) { continue; }
            fat_cutout[i] = last_allocated_cluster_nr;
            last_allocated_cluster_nr = i + FAT32_FatEntriesPerSector * current_sector;
            if (zero_out) {
                err = zero_out_cluster(mnt, last_allocated_cluster_nr);
                if (err_is_fail(err)) {
                    return err;
                }
            }
            counter++;
        }
        err = write_fatcutout(mnt, fat_cutout, mnt->fat_lba + current_sector);
        if (err_is_fail(err)) {
            return err;
        }
        current_sector++;
        if (current_sector >= mnt->sectors_per_fat) {
            current_sector = 0;
        }
    } while(current_sector != start_sector && counter < number_of_clusters);
    if (err_is_fail(err)) {
        return err;
    }
    if (ret_nr_allocated) {
        *ret_nr_allocated = counter;
    }
    if (ret_first_cluster_nr) {
        *ret_first_cluster_nr = last_allocated_cluster_nr;
    }
    mnt->next_free = last_allocated_cluster_nr + 1;
    return SYS_ERR_OK;
}

static errval_t extend_cluster_chain(
    struct fat32_mnt *mnt,
    uint32_t cluster_nr,
    uint32_t n,
    bool zero_out,
    uint32_t *ret_n
) {
    errval_t err;
    uint32_t free_cluster_start_nr;
    err = allocate_clusters(mnt, n, zero_out, ret_n, &free_cluster_start_nr);
    if (err_is_fail(err)) {
        return err;
    }
    uint32_t sector_rel_to_fat = cluster_nr / FAT32_FatEntriesPerSector;
    uint32_t fat_cutout[FAT32_FatEntriesPerSector];
    err = aos_rpc_block_driver_read_block(
        aos_rpc_get_block_driver_channel(),
        mnt->fat_lba + sector_rel_to_fat,
        fat_cutout,
        BLOCK_SIZE
    );
    if (err_is_fail(err)) {
        return err;
    }
    uint32_t offset = cluster_nr % FAT32_FatEntriesPerSector;
    assert(fat_cutout[offset] >= FAT32_EndCluster);
    fat_cutout[offset] = free_cluster_start_nr;
    err = write_fatcutout(mnt, fat_cutout, mnt->fat_lba + sector_rel_to_fat);
    if (err_is_fail(err)) {
        return err;
    }
    return SYS_ERR_OK;
}

static errval_t get_free_dir_entry(
    struct fat32_mnt *mnt,
    struct fat32_handle *parent_handler,
    struct fat32_dirent *dirent
) {
    errval_t err;
    // TODO: Change for long name support
    err = find_dirent(mnt, &parent_handler->dirent, entry_is_unused, NULL, dirent);
    if (err != FS_ERR_NOTFOUND) {
        // Error or we found unused entry
        return err;
    }
    if (dirent->index + 1 >= FAT32_DirEntriesPerBlock * mnt->sectors_per_cluster) {
        // new cluster
        uint32_t n;
        err = extend_cluster_chain(mnt, dirent->cluster, 1, true, &n);
        if (err_is_fail(err)) {
            return err;
        }
        if (n == 0) {
            return FS_ERR_OUT_OF_MEM;
        }
    } else {
        // shift end of dir to next entry
        uint32_t new_end_index = dirent->index + 1;
        uint32_t buf[BLOCK_SIZE];
        struct dir_entry *dir_entry = (struct dir_entry *)&buf;
        err = aos_rpc_block_driver_read_block(
            aos_rpc_get_block_driver_channel(),
            cluster_to_lba(mnt, dirent->cluster) + new_end_index / FAT32_DirEntriesPerBlock,
            buf,
            BLOCK_SIZE
        );
        if (err_is_fail(err)) {
            return err;
        }
        uint32_t offset = new_end_index % FAT32_DirEntriesPerBlock;
        memset(&dir_entry[offset], 0, sizeof(struct dir_entry));
        err = aos_rpc_block_driver_write_block(
            aos_rpc_get_block_driver_channel(),
            cluster_to_lba(mnt, dirent->cluster) + new_end_index / FAT32_DirEntriesPerBlock,
            buf,
            BLOCK_SIZE
        );
        if (err_is_fail(err)) {
            return err;
        }
    }
    return SYS_ERR_OK;
}

/**
 * Initialize a new directory with "." and ".." entries
 * @param mnt
 * @param dirent
 * @return
 */
static errval_t init_new_directory(
    struct fat32_mnt *mnt,
    struct fat32_dirent *dirent
) {
    errval_t err;
    struct dir_entry d[FAT32_DirEntriesPerBlock];
    const uint32_t cluster_nr_dir = get_first_cluster_nr(&dirent->dir_entry);
    err = aos_rpc_block_driver_read_block(
        aos_rpc_get_block_driver_channel(),
        cluster_to_lba(mnt, cluster_nr_dir),
        d,
        BLOCK_SIZE
    );
    if (err_is_fail(err)) {
        return err;
    }
    memset(d, 0, sizeof(d));

    set_dir(&d[0]);
    memset(d[0].shortname, ' ', 11);
    d[0].shortname[0] = '.';
    set_first_cluster_nr(&d[0], cluster_nr_dir);

    set_dir(&d[1]);
    memset(d[1].shortname, ' ', 11);
    d[1].shortname[0] = '.';
    d[1].shortname[1] = '.';
    bool parent_is_root = mnt->root.cluster == dirent->cluster;
    const uint32_t cluster_nr_parent = parent_is_root ? 0 : dirent->cluster;
    set_first_cluster_nr(&d[1], cluster_nr_parent);

    err = aos_rpc_block_driver_write_block(
        aos_rpc_get_block_driver_channel(),
        cluster_to_lba(mnt, cluster_nr_dir),
        d,
        BLOCK_SIZE
    );
    if (err_is_fail(err)) {
        return err;
    }
    return SYS_ERR_OK;
}

/**
 * Create a new file or directory
 * @param mnt Fat32 mount
 * @param path Path to new file/directory
 * @param directory If a directory or a file should be created
 * @param rethandle
 * @return
 */
static errval_t create_data_entry(
    struct fat32_mnt *mnt,
    const char *path,
    bool directory,
    fat32_handle_t *rethandle)
{
    // TODO: Clean up function
    errval_t err;
    err = resolve_path(mnt, &mnt->root, path, NULL);
    if (err_is_ok(err)) {
        return FS_ERR_EXISTS;
    }

    // split parent and child name
    char *lastsep = strrchr(path, FS_PATH_SEP);
    if (lastsep == NULL) {
        return FS_ERR_NOTFOUND;
    }
    const char *childname = lastsep + 1;
    if (! is_valid_name_for_shortname(childname)) { return FS_ERR_INVALID_SHORTNAME; }

    size_t pathlen = lastsep - path;
    char pathbuf[pathlen + 1];
    memcpy(pathbuf, path, pathlen);
    pathbuf[pathlen] = '\0';

    // find parent directory
    struct fat32_handle *parent = NULL;
    err = resolve_path(mnt, &mnt->root, pathbuf, &parent);
    if (err_is_fail(err)) {
        return err;
    } else if (!parent->isdir) {
        err = FS_ERR_NOTDIR; // parent is not a directory
        goto cleanup;
    }

    struct fat32_dirent dirent;
    err = get_free_dir_entry(mnt, parent, &dirent);
    if (err_is_fail(err)) {
        goto cleanup;
    }
    memset(&dirent.dir_entry, 0, sizeof(struct dir_entry));
    name_to_shortname(childname, dirent.dir_entry.shortname);
    uint32_t n;
    uint32_t cluster_nr;
    err = allocate_clusters(mnt, 1, !directory, &n, &cluster_nr);
    if (err_is_fail(err)) {
        goto cleanup;
    }
    if (n < 1) {
        err = FS_ERR_OUT_OF_MEM;
        goto cleanup;
    }
    set_first_cluster_nr(&dirent.dir_entry, cluster_nr);
    if (directory) {
        set_dir(&dirent.dir_entry);
        init_new_directory(mnt, &dirent);
    }

    err = update_dir_entry_on_disk(mnt, &dirent);
    if (err_is_fail(err)) {
        goto cleanup;
    }

    if (rethandle) {
        struct fat32_handle *fh = handle_open(&dirent, path);
        if (fh  == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        *rethandle = fh;
    }
    err = SYS_ERR_OK;
    cleanup:
    if (parent) {
        handle_close(parent);
    }
    return err;
}

errval_t fat32_create(
    void *st,
    const char *path,
    fat32_handle_t *rethandle
) {
    return create_data_entry(
        (struct fat32_mnt *)st,
        path,
        false,
        rethandle
    );
}

errval_t fat32_mkdir(void *st, const char *path)
{
    return create_data_entry(
        (struct fat32_mnt *)st,
        path,
        true,
        NULL
    );
}

static errval_t travers_fat(
    struct fat32_mnt *mnt,
    uint32_t cluster_start,
    uint32_t *ret_number_of_clusters,
    uint32_t *ret_last_cluster_nr
) {
    errval_t err;
    uint32_t fat_cutout[BLOCK_SIZE / sizeof(uint32_t)];
    uint32_t cluster_nr = cluster_start;
    uint32_t counter = 0;
    uint32_t index = mnt->fat_lba + cluster_nr / FAT32_FatEntriesPerSector;
    uint32_t prev_index = index - 1;
    uint32_t prev_cluster_nr = cluster_nr;

    while (cluster_nr < FAT32_EndCluster) {
        // Only read when new block is accessed
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
        prev_cluster_nr = cluster_nr;
        cluster_nr = fat_cutout[prev_cluster_nr % FAT32_FatEntriesPerSector];
        prev_index = index;
        index = mnt->fat_lba + cluster_nr / FAT32_FatEntriesPerSector;
        counter++;
    }
    if (ret_number_of_clusters) {
        *ret_number_of_clusters = counter;
    }
    if (ret_last_cluster_nr) {
        *ret_last_cluster_nr = prev_cluster_nr;
    }
    return SYS_ERR_OK;
}

static errval_t calculate_additional_cluster_required(
    struct fat32_mnt *mnt,
    struct fat32_handle *h,
    uint32_t new_end,
    uint32_t *ret_n_clusters_required,
    uint32_t *ret_last_cluster
) {
    errval_t err;
    const uint32_t bytes_per_cluster = BLOCK_SIZE * mnt->sectors_per_cluster;
    uint32_t n_clusters_required;
    uint32_t n_clusters;
    uint32_t last_cluster;

    err = travers_fat(mnt, get_first_cluster_nr(&h->dirent.dir_entry), &n_clusters, &last_cluster);
    if (err_is_fail(err)) {
        return err;
    }
    n_clusters_required = ROUND_UP(new_end, bytes_per_cluster) / bytes_per_cluster;
    n_clusters_required -= n_clusters;

    if (ret_n_clusters_required) {
        *ret_n_clusters_required = n_clusters_required;
    }
    if (ret_last_cluster){
        *ret_last_cluster = last_cluster;
    }
    return SYS_ERR_OK;
}

errval_t fat32_write(
    void *st,
    fat32_handle_t handle,
    const void *buffer,
    size_t bytes,
    size_t *bytes_written
) {
    struct fat32_mnt *mnt = st;
    struct fat32_handle *h = handle;
    errval_t err;
    if (h->isdir) {
        return FS_ERR_NOTFILE;
    }
    if (h->file_pos + bytes < h->file_pos) {
        // TODO: Better error code
        return FS_ERR_OUT_OF_MEM;
    }
    if (h->dirent.dir_entry.size < h->file_pos + bytes) {
        uint32_t n_new_clusters;
        uint32_t last_cluster;
        err = calculate_additional_cluster_required(
            mnt,
            h,
            h->file_pos + bytes,
            &n_new_clusters,
            &last_cluster
        );
        if (err_is_fail(err)) {
            return err;
        }
        if (n_new_clusters) {
            err = extend_cluster_chain(mnt, last_cluster, n_new_clusters, true, NULL);
            if (err_is_fail(err)) {
                return err;
            }
        }
        // TODO: Zero from size to end of last_cluster
    }

    uint8_t block[BLOCK_SIZE];
    uint32_t b_written = 0;
    while (b_written < bytes && h->current_cluster < FAT32_EndCluster) {
        uint32_t offset = h->file_pos % BLOCK_SIZE;
        uint32_t to_write = MIN(BLOCK_SIZE - offset, bytes - b_written);
        uint32_t index = cluster_to_lba(mnt, h->current_cluster) + h->sector_rel_cluster;
        if (to_write != BLOCK_SIZE) {
            err = aos_rpc_block_driver_read_block(
                aos_rpc_get_block_driver_channel(),
                index,
                block,
                BLOCK_SIZE
            );
            if (err_is_fail(err)) {
                return err;
            }
        }
        memcpy(block + offset, buffer + b_written, to_write);
        err = aos_rpc_block_driver_write_block(
            aos_rpc_get_block_driver_channel(),
            index,
            block,
            BLOCK_SIZE
        );
        if (err_is_fail(err)) {
            return err;
        }
        b_written += to_write;
        h->file_pos += to_write;
        h->sector_rel_cluster++;
        if (h->sector_rel_cluster >= mnt->sectors_per_cluster) {
            h->sector_rel_cluster = 0;
            // TODO: optimize -> next_cluster rereads the fat several time even when same
            //       cutout is needed
            err = next_cluster(mnt, h->current_cluster, &h->current_cluster);
            if (err_is_fail(err)) {
                return err;
            }
        }
    }
    if (bytes_written) {
        *bytes_written = b_written;
    }
    h->dirent.dir_entry.size = MAX(h->dirent.dir_entry.size, h->file_pos);
    return update_dir_entry_on_disk(mnt, &h->dirent);
}

#pragma GCC diagnostic pop
