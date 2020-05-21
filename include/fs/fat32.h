//
// Created by loris on 18/05/2020.
//

#ifndef BF_AOS_FAT32_H
#define BF_AOS_FAT32_H

#include <stdint.h>
#include <fs/fs.h>

typedef void *fat32_handle_t;

#define BLOCK_SIZE 512
#define BPB_BytsPerSec 0x0b
#define BPB_SecPerClus 0x0d
#define BPB_NumFATs    0x10
#define BPB_RsvdSecCnt 0x0e
#define BPB_FATSz32    0x24
#define BPB_RootClus   0x2c

struct dir_entry {
    char shortname[11];
    uint8_t attr;
    uint8_t ntr;
    uint8_t crt_time_tenth;
    uint8_t _unused[6];
    uint16_t first_cluster_hi;
    uint16_t write_time;
    uint16_t write_date;
    uint16_t first_cluster_lo;
    uint32_t size;
} __attribute__((packed));

struct fat32_dirent {
    struct dir_entry dir_entry;
    uint32_t cluster;
    uint32_t offset;
};

struct fat32_mnt {
    struct fat32_dirent root;
    uint32_t fat_lba;
    uint32_t cluster_begin_lba;
    uint32_t root_dir_first_cluster;
    uint32_t sector_per_fat;
    uint16_t reserved_sector_count;
    uint8_t sectors_per_cluster;
    uint8_t number_of_fats;
    const char *mount_point;
};

struct fat32_handle {
    struct fat32_dirent dirent;
    uint32_t current_cluster;
    uint32_t sector_rel_cluster;    ///< The sector we are at, relative to the cluster
    union {
        uint32_t dir_offset;        ///< Dir entry offset relative to the current sector
        uint32_t file_pos;          ///< The file position of the current file handler
    };
    char *path;
    bool isdir;
};

errval_t mount_fat32(const char *name, struct fat32_mnt **fat_mnt);
errval_t fat32_opendir(
    void *st,
    const char *path,
    fat32_handle_t *rethandle
);

errval_t fat32_dir_read_next(
    void *st,
    fat32_handle_t inhandle,
    char **retname,
    struct fs_fileinfo *info
);
errval_t fat32_closedir(
    void *st,
    fat32_handle_t dhandle
);

errval_t fat32_open(void *st, const char *path, fat32_handle_t *rethandle);
errval_t fat32_close(void *st, fat32_handle_t inhandle);
errval_t fat32_tell(void *st, fat32_handle_t handle, size_t *pos);
errval_t fat32_stat(void *st, fat32_handle_t inhandle, struct fs_fileinfo *info);
errval_t fat32_read(
    void *st,
    fat32_handle_t handle,
    void *buffer,
    size_t bytes,
    size_t *bytes_read
);
errval_t fat32_seek(
    void *st,
    fat32_handle_t handle,
    enum fs_seekpos whence,
    off_t offset
);

#endif //BF_AOS_FAT32_H
