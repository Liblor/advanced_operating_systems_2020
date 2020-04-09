/**
 * \file coreboot.h
 * \brief boot new core
 */

/*
 * Copyright (c) 2020, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef LIBBARRELFISH_COREBOOT_H
#define LIBBARRELFISH_COREBOOT_H

#include <sys/cdefs.h>

__BEGIN_DECLS

/**
 * \brief Boot a core
 *
 * \param mpid          The ARM MPID of the core to be booted    
 * \param boot_driver   Name of the boot driver binary
 * \param cpu_driver    Name of the CPU driver
 * \param init          The name of the init binary
 * \param urpc_frame_id Description of what will be passed as URPC frame
 *
 */
errval_t coreboot(coreid_t mpid,
        const char *boot_driver,
        const char *cpu_driver,
        const char *init,
        struct frame_identity urpc_frame_id);


__END_DECLS

#endif
