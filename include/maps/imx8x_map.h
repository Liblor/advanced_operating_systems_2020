/**
 * \file
 * \brief Physical memory map for NXP i.MX8X SoC family. 
 */

/*
 * Copyright (c) 2012, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstrasse 6, CH-8092 Zurich. 
 * Attn: Systems Group.
 */

#ifndef IMX8X_MAP_H
#define IMX8X_MAP_H

/*
 * Devices Range: most of the device are in here
 */
#define IMX8X_START_DEV_RANGE 0x50000000
#define IMX8X_SIZE_DEV_RANGE 0x10000000

/*
 * UART
 */ 

#define IMX8X_UART0_BASE 0x5A060000
#define IMX8X_UART1_BASE 0x5A070000
#define IMX8X_UART2_BASE 0x5A080000
#define IMX8X_UART3_BASE 0x5A090000
#define IMX8X_UART_SIZE 0x1000

/*
 * ENET
 */ 

#define IMX8X_ENET_BASE 0x5B040000
#define IMX8X_ENET_SIZE 0x1000
/*
 * GIC Distributor
 */
#define IMX8X_GIC_DIST_BASE 0x51A00000
#define IMX8X_GIC_DIST_SIZE 0x1000


/*
 * SDHC
 */
#define IMX8X_SDHC1_BASE 0x5B010000   /* connected to the onboard flash */
#define IMX8X_SDHC2_BASE 0x5B020000   /* connected to the SD card*/
#define IMX8X_SDHC_SIZE 0x1000

#endif  // IMX8X_MAP_H
