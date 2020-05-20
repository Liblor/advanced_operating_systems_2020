//
// Created by loris on 18/05/2020.
//

#ifndef BF_AOS_FAT32_H
#define BF_AOS_FAT32_H

#include <stdint.h>

typedef void *fat32_handle_t;

#define BLOCK_SIZE 512
#define BPB_BytsPerSec 0x0b
#define BPB_SecPerClus 0x0d
#define BPB_NumFATs    0x10
#define BPB_RsvdSecCnt 0x0e
#define BPB_FATSz32    0x24
#define BPB_RootClus   0x2c

struct fat32_mnt {
    uint32_t fat_lba;
    uint32_t cluster_begin_lba;
    uint32_t root_dir_first_cluster;
    uint32_t sector_per_fat;
    uint16_t reserved_sector_count;
    uint8_t sectors_per_cluster;
    uint8_t number_of_fats;
};

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

struct fat32_handle {
    char *path;
    bool isdir;
    uint32_t cluster;
};

errval_t mount_fat32(const char *name, struct fat32_mnt **fat_mnt);

#endif //BF_AOS_FAT32_H
