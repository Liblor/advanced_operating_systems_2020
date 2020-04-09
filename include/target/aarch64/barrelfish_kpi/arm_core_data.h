/**
 * \file
 * \brief Data sent to a newly booted kernel
 */

/*
 * Copyright (c) 2012, 2017 ETH Zurich.
 * Copyright (c) 2015, 2016 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _AARCH64_COREDATA_H
#define _AARCH64_COREDATA_H

#include <aos/static_assert.h>


struct armv8_coredata_elf {
    uint32_t    num;
    uint32_t    size;
    uint32_t    addr;
    uint32_t    shndx;
};

#define ARMV8_BOOTMAGIC_BSP     0xb001b000
#define ARMV8_BOOTMAGIC_PSCI    0xb001b001
#define ARMV8_BOOTMAGIC_PARKING 0xb001b002

struct armv8_coredata_memreg
{
    genpaddr_t base;
    gensize_t length;
};

/**
 * \brief Data sent to a newly booted kernel
 *
 */
struct armv8_core_data {

    /**
     * ARMv8 Boot magic field. Contains the value ARMV8_BOOTMAGIC_*
     */
    uint64_t boot_magic;

    /**
     * Physical address of the kernel stack. Allocate at least 16 pages
     * for the stack. Remember the stack grows down, so this should
     * point to the highest address in the allocated range.
     */
    genpaddr_t cpu_driver_stack;

    /**
     * Physical address of the kernel stack limit
     */
    genpaddr_t cpu_driver_stack_limit;

    /**
     * Physical address of the global data structure shared by all.
     * Will be set by the initiating core, userspace does not have to set it.
     */
    genpaddr_t cpu_driver_globals_pointer;

    /**
     * Virtual address of CPU Driver entry point. Should point to
     * 'arch_init', in virtual address space.
     */
    genvaddr_t cpu_driver_entry;

    /**
     * CPU driver command line arguments. Setting everything to zero
     * is valid for passing no arguments.
     */
    char cpu_driver_cmdline[128];

    /**
     * Physical address of the L0 page table in memory. 
     * Will be set by the initiating core, userspace does not have to set it.
     */
    genpaddr_t page_table_root;

    /**
     * Memory region to be used for the new CPU driver's allocations.
     * This should be at least ARMV8_CORE_DATA_PAGES * BASE_PAGE_SIZE
     * + the size of the monitor process (use elf_virtual_size to
     * determine the size of the monitor process).
     */
    struct armv8_coredata_memreg memory;

    /**
     * Memory region to be used for the URPC frame for the monitor process. 
     */
    struct armv8_coredata_memreg urpc_frame;

    /**
     * Memory region where the CPU driver will look for an ELF image of the
     * monitor process to be created.
     */
    struct armv8_coredata_memreg monitor_binary;

    /**
     * memory region of the multiboot image.
     * Does not have to be set for APP cores.
     */
    struct armv8_coredata_memreg multiboot_image;

    /* Does not have to be set for APP cores. */
    lpaddr_t efi_mmap;

    /**
     * The physical start of allocated kernel memory
     * Does not have to be set for APP cores.
     */
    uint64_t    start_kernel_ram; 

    /**
     * The physical start of free ram for the bsp allocator
     * Does not have to be set for APP cores.
     */
    uint64_t    start_free_ram; 

    /**
     * Does not have to be set for APP cores.
     */
    uint32_t    chan_id;

    /**
     * Physical address of the kernel control block
     */
    genpaddr_t kcb; 


    /**
     * Logical core id of the invoking core. You are free to use any 
     * naming scheme you like. A simple solution is to use the ARM mpid.
     */
    coreid_t src_core_id;

    /**
     * Logical core id of the started core
     */
    coreid_t dst_core_id;

    /**
     * Physical core id of the invoking core. This must be a valid ARM mpid.
     * You can use disp_get_core_id() to obtain the current's core mpid. 
     */
    hwid_t src_arch_id;

    /**
     * Physical core id of the started core. This must be a valid ARM mpid
     */
    hwid_t dst_arch_id;


};

STATIC_ASSERT(sizeof(struct armv8_core_data) < 4096,
        "Core Data structure must not exceed page size");

#define ARMV8_CORE_DATA_PAGES 1200


#endif
