/*
 * Copyright (c) 2013, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef DRIVERKIT_H
#define DRIVERKIT_H

#include <aos/types.h>
#include <errors/errno.h>
#include <collections/list.h>

///< represents a device address
typedef genpaddr_t dmem_daddr_t;

/**
 * @brief represents a region of device memory
 *
 * this region is intended to be used between the device and the driver.
 */
struct dmem
{
    ///< address as seen by the device
    dmem_daddr_t            devaddr;

    ///< address as seen by the driver
    lvaddr_t                vbase;

    ///< capability referring to the memory resource
    struct capref           mem;

    ///< size of the memory region in bytes
    gensize_t               size;

    ///< iommu client state
    struct iommu_client    *cl;
};


errval_t map_device_register(lpaddr_t address, size_t size, struct capref* return_cap,
                             lvaddr_t *return_address);

#endif // DRIVERKIT_H
