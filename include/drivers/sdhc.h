/*
 * Copyright (c) 2020, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr 6, CH-8092 Zurich.
 */

#ifndef SDHC_H_
#define SDHC_H_

#include <stdint.h>
#include <aos/aos.h>

#define IMX8X_SDHC0_INT 264
#define IMX8X_SDHC1_INT 265
#define IMX8X_SDHC2_INT 266

#define SDHC_BLOCK_SIZE 512
#define SDHC_TEST_BLOCK 20

struct sdhc_s;
/**
 * Allocate and initialize the SDHC driver. Ensure that base is mapped as
 * read/write and nocache. The sd struct must be freed by the caller.
 *
 * \param sd   The driver struct
 * \param base Register base of the SDHC controller.
 */
errval_t sdhc_init(struct sdhc_s** sd, void *base);

/**
 * Test the SD card by writing, reading and verifying SDHC_TEST_BLOCK.
 * The test function assumes the scratch region is mapped NOCACHE.
 * WARNING: This will alter the SD card contents.
 *
 * \param sd        The driver struct
 * \param scratch   Scratch region virtual address
 * \param scratch_p Scratch region physical address
 *
 */
errval_t sdhc_test(struct sdhc_s* sd, void * scratch, lpaddr_t scratch_p);

/**
 * Write a block of SDHC_BLOCK_LEN bytes located at source to block index. 
 * The caller must ensure the right memory fences are in place and the DMA
 * of the device can actually read from physical memory.
 * This call will block until the data has been written.
 *
 * \param sd        The driver struct
 * \param index     The block index to write
 * \param source    Physical address of the data to read from
 */
errval_t sdhc_write_block(struct sdhc_s* sd, int index, lpaddr_t source);

/**
 * Read block number index of SDHC_BLOCK_LEN bytes to physical address dest
 * The caller must invalidate his cache to ensure it can read the data
 * after this function returns.
 * This call will block until the data has been read.
 *
 * \param sd        The driver struct
 * \param index     The block index to read
 * \param dest      Physical address where to write
 */
errval_t sdhc_read_block(struct sdhc_s* sd, int index, lpaddr_t dest);

#endif
