/*
 * Copyright (c) 2016, ETH Zurich.
 *
 * This file is distributed under the terms in the attached LICENSE file.  If
 * you do not find this file, copies can be found by writing to: ETH Zurich
 * D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef __KERNEL_CAP_INVOCATIONS
#define __KERNEL_CAP_INVOCATIONS

#include <aos/aos.h>

#define DEBUG_INVOCATION(x...)

/**
 * \brief Spawn a new core.
 *
 * \param core_id    MPID of the core to be booted
 * \param cpu_type   Barrelfish target CPU type
 * \param core_data  Address of struct core_data for new core in kernel-virtual
 *                   memory
 */

static inline errval_t
invoke_monitor_spawn_core(hwid_t core_id, enum cpu_type cpu_type,
                          genpaddr_t entry, genpaddr_t context,
                          uint64_t psci_use_hvc)
{
    DEBUG_INVOCATION("%s: called from %p\n", __FUNCTION__,
            __builtin_return_address(0));
    return cap_invoke6(cap_ipi, IPICmd_Send_Start, core_id, cpu_type,
                       entry, context, psci_use_hvc).error;
}

static inline errval_t
invoke_monitor_create_cap(uint64_t *raw, capaddr_t caddr, int level,
        capaddr_t slot, coreid_t owner)
{
    DEBUG_INVOCATION("%s: called from %p\n", __FUNCTION__,
            __builtin_return_address(0));
    return cap_invoke6(cap_kernel, KernelCmd_Create_cap, caddr, level, slot,
                       owner, (uintptr_t)raw).error;
}

/**
 * \brief Create a RAM cap ab initio, by invoking the kernel cap.
 *
 * \param dest   Location to place new RAM cap
 * \param base   Base address of the region
 * \param bytes  Size of region to create
 * \param coreid Which core should own the capability
 *
 * Forges a capability to the given region of physical memory.  This is only
 * possible in domains that have access to the kernel capability, and is an
 * inherently unsafe operation, as it bypasses all checks in the capability
 * system.  As the CPU drivers don't communicate directly however, this is the
 * only way to transfer a capability between cores.  This must *only* be used
 * for the root RAM region to be managed by a newly-booted core - if used for
 * anything else, it will break things, *badly*.
 *
 * XXX Warning Warning Warning
 * XXX Again - be *very* careful with this, and make sure you understand what
 * it's doing.  You're establishing the *root of trust* for the new core.  If
 * you use this for *anything* else, you're doing it wrong!
 * XXX Warning Warning Warning
 *
 */
static inline errval_t
ram_forge(struct capref dest, genpaddr_t base, gensize_t bytes,
                   coreid_t coreid) {
    struct capability ram_cap = {
        .type = ObjType_RAM,
        .rights = CAPRIGHTS_READ_WRITE,
        .u.ram = {
            .base  = base,
            .pasid = 0,
            .bytes = bytes
        }
    };

    return invoke_monitor_create_cap((uint64_t *)&ram_cap,
                                     get_cnode_addr(dest),
                                     get_cnode_level(dest),
                                     dest.slot, coreid);
}

/**
 * \brief Create a Frame cap ab initio, by invoking the kernel cap.
 *
 * \param dest   Location to place new Frame cap
 * \param base   Base address of the region
 * \param bytes  Size of region to create
 * \param coreid Which core should own the capability
 *
 * As for ram_forge, but for frames.  Same warnings apply!
 *
 */
static inline errval_t
frame_forge(struct capref dest, genpaddr_t base, gensize_t bytes,
                     coreid_t coreid) {
    struct capability frame_cap = {
        .type = ObjType_Frame,
        .rights = CAPRIGHTS_READ_WRITE,
        .u.frame = {
            .base  = base,
            .bytes = bytes
        }
    };

    return invoke_monitor_create_cap((uint64_t *)&frame_cap,
                                     get_cnode_addr(dest),
                                     get_cnode_level(dest),
                                     dest.slot, coreid);
}

/**
 * \brief Create a DevFrame cap ab initio, by invoking the kernel cap.
 *
 * \param dest   Location to place new Frame cap
 * \param base   Base address of the region
 * \param bytes  Size of region to create
 * \param coreid Which core should own the capability
 *
 * As for ram_forge, but for devframes.  Same warnings apply!
 *
 */
static inline errval_t
devframe_forge(struct capref dest, genpaddr_t base, gensize_t bytes,
                        coreid_t coreid) {
    struct capability frame_cap = {
        .type = ObjType_DevFrame,
        .rights = CAPRIGHTS_READ_WRITE,
        .u.frame = {
            .base  = base,
            .bytes = bytes
        }
    };

    return invoke_monitor_create_cap((uint64_t *)&frame_cap,
                                     get_cnode_addr(dest),
                                     get_cnode_level(dest),
                                     dest.slot, coreid);
}




#endif /* __KERNEL_CAP_INVOCATIONS */
