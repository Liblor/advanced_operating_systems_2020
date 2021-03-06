/**
 * \file
 * \brief
 */

/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2019, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#ifndef LIBBARRELFISH_CORESTATE_H
#define LIBBARRELFISH_CORESTATE_H

#include <k_r_malloc.h>
#include <aos/waitset.h>
#include <aos/ram_alloc.h>
#include <aos/paging.h>
#include <aos/slot_alloc.h>
#include <aos/thread_sync.h>
#include <barrelfish_kpi/paging_arch.h>
#include <barrelfish_kpi/capabilities.h>
#include <barrelfish_kpi/init.h> // for CNODE_SLOTS_*

// "region" of addresses that are reserved in morecore_state
struct morecore_zone {
    lvaddr_t base_addr;
    lvaddr_t current_addr;
    size_t region_size;
};

/// a morecore zone with memory which is always eagerly backed by frames
struct morecore_static_zone {
    lvaddr_t base_addr;
    lvaddr_t current_addr;       /// < everything below this is handed out
    size_t backed_size;          /// < how much starting from base_addr is backed
    size_t region_size;          /// < total area of the zone
    bool is_refilling;
};

struct morecore_state {
    struct thread_mutex *mutex;

    Header header_base;
    Header *header_freep;

    struct morecore_zone dynamic_zone;
    struct morecore_static_zone static_zone;

    struct paging_region dynamic_heap_pr;

    // for initial static morecore
    char *freep;

    bool heap_static;

    // malloc state for static
    Header header_base_static;
    Header *header_freep_static;

    // malloc state for dynamic
    Header header_base_dynamic;
    Header *header_freep_dynamic;
};

struct ram_alloc_state {
    bool mem_connect_done;
    errval_t mem_connect_err;
    struct thread_mutex ram_alloc_lock;
    ram_alloc_func_t ram_alloc_func;
    uint64_t default_minbase;
    uint64_t default_maxlimit;
    int base_capnum;
};


struct slot_alloc_state {
    struct multi_slot_allocator defca;

    struct single_slot_allocator top;
    struct slot_allocator_list head;
    struct slot_allocator_list extra; // for 2level cspace
    struct slot_allocator_list reserve;

    char     top_buf[SINGLE_SLOT_ALLOC_BUFLEN(SLOT_ALLOC_CNODE_SLOTS)];
    char    head_buf[SINGLE_SLOT_ALLOC_BUFLEN(SLOT_ALLOC_CNODE_SLOTS)];
    char reserve_buf[SINGLE_SLOT_ALLOC_BUFLEN(SLOT_ALLOC_CNODE_SLOTS)];
    char    root_buf[SINGLE_SLOT_ALLOC_BUFLEN(L2_CNODE_SLOTS)];

    struct single_slot_allocator rootca;
};

struct terminal_state;
struct domain_state;
struct spawn_state;
struct aos_chan;
struct mem_rpc_client;
struct spawn_rpc_client;
struct paging_state;

struct core_state_generic {
    struct waitset default_waitset;
    struct aos_chan *init_chan;
    struct aos_rpc *init_rpc;
    struct morecore_state morecore_state;
    struct paging_state *paging_state;
    struct ram_alloc_state ram_alloc_state;
    struct slot_alloc_state slot_alloc_state;
};

#endif
