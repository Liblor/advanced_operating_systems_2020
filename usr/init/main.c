/**
 * \file
 * \brief init process for child spawning
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <aos/capabilities.h>
#include <mm/mm.h>
#include <spawn/spawn.h>
#include <grading.h>

#include "mem_alloc.h"
#include "initserver.h"
#include "memoryserver.h"
#include "serialserver.h"
#include "processserver.h"
#include "test.h"

struct bootinfo *bi;

coreid_t my_core_id;

static void number_cb(uintptr_t num)
{
    grading_rpc_handle_number(num);

    debug_printf("Received number %"PRIuPTR"\n", num);
}

static void string_cb(char *c)
{
    grading_rpc_handler_string(c);

    debug_printf("Received string %s\n", c);
}

// We do not allocate RAM here. This should be done in the server itself.
static errval_t ram_cap_cb(const size_t bytes, const size_t alignment, struct capref *retcap, size_t *retbytes)
{
    errval_t err;

    grading_rpc_handler_ram_cap(bytes, alignment);

    debug_printf("ram_cap_cb(bytes=0x%zx, alignment=0x%zx)\n", bytes, alignment);

    err = ram_alloc_aligned(retcap, bytes, alignment);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "ram_alloc_aligned() failed");
        return err_push(err, LIB_ERR_RAM_ALLOC);
    }

    struct capability cap;
    err = cap_direct_identify(*retcap, &cap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "cap_direct_identify() failed");
        return err_push(err, LIB_ERR_CAP_IDENTIFY);
    }

    *retbytes = get_size(&cap);
    HERE;

    debug_printf("allocated %d size\n", *retbytes);
    return SYS_ERR_OK;
}

static void putchar_cb(char c) {
    errval_t err;

    grading_rpc_handler_serial_putchar(c);

    err = sys_print((const char *)&c, 1);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sys_print() failed");
    }
}

static void getchar_cb(char *c) {
    errval_t err;

    grading_rpc_handler_serial_getchar();

    err = sys_getchar(c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "sys_getchar() failed");
    }
}

static errval_t spawn_cb(char *name, coreid_t coreid, domainid_t *ret_pid)
{
    errval_t err;

    grading_rpc_handler_process_spawn(name, coreid);

    struct spawninfo si;

    err = add_to_proc_list(name, ret_pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "add_to_proc_list()");
        return err;
    }

    err = spawn_load_by_name(name, &si, ret_pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "spawn_load_by_name()");
        // TODO: If spawn failed, remove the process from the processserver state list.
        return err;
    }

    debug_printf("new pid is %d\n", *ret_pid);

    return SYS_ERR_OK;
}

static errval_t get_name_cb(domainid_t pid, char **ret_name) {
    errval_t err;

    grading_rpc_handler_process_get_name(pid);

    err = get_name_by_pid(pid, ret_name);

    return err;
}

static errval_t process_get_all_pids(size_t *ret_count, domainid_t **ret_pids) {
    errval_t err;

    grading_rpc_handler_process_get_all_pids();

    err = get_all_pids(ret_count, ret_pids);

    return err;
}

static int bsp_main(int argc, char *argv[])
{
    errval_t err;

    // Grading
    grading_setup_bsp_init(argc, argv);

    // First argument contains the bootinfo location, if it's not set
    bi = (struct bootinfo*)strtol(argv[1], NULL, 10);
    assert(bi);

    err = initialize_ram_alloc();
    if(err_is_fail(err)){
        DEBUG_ERR(err, "initialize_ram_alloc");
    }

    // TODO: Remove.
    //test_libmm();
    //test_paging();
    //test_paging_multi_pagetable();

    // TODO: initialize mem allocator, vspace management here

    // Grading
    //grading_test_early();

    // TODO: Spawn system processes, boot second core etc. here

    err = initserver_init(number_cb, string_cb);
    if (err_is_fail(err)) {
        debug_printf("initserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    err = memoryserver_init(ram_cap_cb);
    if (err_is_fail(err)) {
        debug_printf("memoryserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    err = serialserver_init(putchar_cb, getchar_cb);
    if (err_is_fail(err)) {
        debug_printf("serialserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    err = processserver_init(spawn_cb, get_name_cb, process_get_all_pids);
    if (err_is_fail(err)) {
        debug_printf("processserver_init() failed: %s\n", err_getstring(err));
        abort();
    }

    //char *binary_name1 = "memeater";
    //struct spawninfo si1;
    //domainid_t pid1;

    //err = spawn_load_by_name(binary_name1, &si1, &pid1);
    //if (err_is_fail(err)) {
    //    DEBUG_ERR(err, "in event_dispatch");
    //    abort();
    //}

    char *binary_name2 = "memeater";
    struct spawninfo si2;
    domainid_t pid2;

    err = spawn_load_by_name(binary_name2, &si2, &pid2);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "in event_dispatch");
        abort();
    }

    // Grading
    grading_test_late();

    debug_printf("Message handler loop\n");
    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
    }

    return EXIT_SUCCESS;
}

static int app_main(int argc, char *argv[])
{
    // Implement me in Milestone 5
    // Remember to call
    // - grading_setup_app_init(..);
    // - grading_test_early();
    // - grading_test_late();
    return LIB_ERR_NOT_IMPLEMENTED;
}

int main(int argc, char *argv[])
{
    errval_t err;

    /* Set the core id in the disp_priv struct */
    err = invoke_kernel_get_core_id(cap_kernel, &my_core_id);
    assert(err_is_ok(err));
    disp_set_core_id(my_core_id);

    debug_printf("init: on core %" PRIuCOREID ", invoked as:", my_core_id);
    for (int i = 0; i < argc; i++) {
       printf(" %s", argv[i]);
    }
    printf("\n");
    fflush(stdout);

    if(my_core_id == 0) return bsp_main(argc, argv);
    else                return app_main(argc, argv);
}
