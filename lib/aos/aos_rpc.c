/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached license file.
 * if you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. attn: systems group.
 */

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/urpc.h>
#include <aos/slot_alloc.h>

void aos_rpc_handler_print(char* string, uintptr_t* val, struct capref* cap)
{
    aos_rpc_lmp_handler_print(string, val, cap);
}

errval_t aos_rpc_init(struct aos_rpc *rpc, enum aos_rpc_type type)
{
    memset(rpc, 0, sizeof(struct aos_rpc));

    thread_mutex_init(&rpc->mutex);
    rpc->type = type;

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    return aos_rpc_lmp_send_number(rpc, num);
}

errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    return aos_rpc_lmp_send_string(rpc, string);
}

errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment, struct capref *ret_cap, size_t *ret_bytes)
{

    // We have to ensure that there are enough slots available prior to using
    // the channel. We have to make sure the channel is used atomically, i.e.,
    // there are no subsequent calls in the same callstack, so that the channel
    // context can be used.
    slot_ensure_threshold(32);

    return aos_rpc_lmp_get_ram_cap(rpc, bytes, alignment, ret_cap, ret_bytes);
}

errval_t aos_rpc_get_remote_ram_cap(
        size_t bytes,
        size_t alignment,
        coreid_t coreid,
        struct capref *ret_cap,
        size_t *ret_bytes
)
{
    slot_ensure_threshold(32);

    // use lmp if own core
    if (coreid == disp_get_core_id()) {
        return aos_rpc_lmp_get_ram_cap(
                aos_rpc_get_memory_channel(),
                bytes,
                alignment,
                ret_cap,
                ret_bytes);
    } else {
        return aos_rpc_lmp_get_ram_cap(
                aos_rpc_get_init_channel(),
                bytes,
                alignment,
                ret_cap,
                ret_bytes);

    }
}

errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    return aos_rpc_lmp_serial_getchar(rpc, retc);
}

errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    return aos_rpc_lmp_serial_putchar(rpc, c);
}

errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline, coreid_t core, domainid_t *newpid)
{
    return aos_rpc_lmp_process_spawn(rpc, cmdline, core, newpid);
}

errval_t aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name)
{
    return aos_rpc_lmp_process_get_name(rpc, pid, name);
}

errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids, size_t *pid_count)
{
    return aos_rpc_lmp_process_get_all_pids(rpc, pids, pid_count);
}

errval_t aos_rpc_get_device_cap(struct aos_rpc *rpc, lpaddr_t paddr, size_t bytes, struct capref *ret_cap)
{
    return aos_rpc_lmp_get_device_cap(rpc, paddr, bytes, ret_cap);
}

/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void)
{
    return aos_rpc_lmp_get_init_channel();
}

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void)
{
    return aos_rpc_lmp_get_memory_channel();
}

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void)
{
    return aos_rpc_lmp_get_process_channel();
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void)
{
    return aos_rpc_lmp_get_serial_channel();
}
