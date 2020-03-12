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
#include <mm/mm.h>
#include <grading.h>

#include "mem_alloc.h"

struct bootinfo *bi;

coreid_t my_core_id;

// ----------------------------------------------------------
// tests
// ----------------------------------------------------------
__attribute__ ((unused)) static void test_simple_alloc_free(void) {
    errval_t err;
    struct capref retcap1;
    struct capref retcap2;
    err = mm_alloc(&aos_mm, 1 << 20, &retcap1);
    assert(err_is_ok(err));

    {
        struct capability tmp_cap;
        cap_direct_identify(retcap1, &tmp_cap);
        genpaddr_t base = get_address(&tmp_cap);
        gensize_t size = get_size(&tmp_cap);
        err = mm_free(&aos_mm, retcap1, base, size);
        assert(err_is_ok(err));

    }
    err = mm_alloc(&aos_mm, 1 << 10, &retcap2);
    assert(err_is_ok(err));
    err = mm_alloc(&aos_mm, 1 << 20, &retcap1);
    assert(err_is_ok(err));
    {
        struct capability tmp_cap;
        cap_direct_identify(retcap2, &tmp_cap);
        genpaddr_t base = get_address(&tmp_cap);
        gensize_t size = get_size(&tmp_cap);
        err = mm_free(&aos_mm, retcap2, base, size);
        assert(err_is_ok(err));
    }
}

__attribute__ ((unused))static void test_handle_slot_256(void) {
    errval_t err;
    const uint64_t size = 260;
//    static char nodebuf[1 << 20];
//    slab_grow(&aos_mm.slabs, nodebuf, sizeof(nodebuf));

    struct capref retcaps[size];
    for (int i = 0; i < size; ++i) {
        err = aos_mm.slot_alloc(aos_mm.slot_alloc_inst, 1, &retcaps[i]);
        assert(err_is_ok(err));
    }
    for (int i = 0; i < size; ++i) {
        err = slot_free(retcaps[i]);
        assert(err_is_ok(err));
    }
    DEBUG_PRINTF("success\n");
}

__attribute__ ((unused))static void test_slab_simple(void) {
    errval_t err;
    const uint64_t size = 260;
    struct capref retcaps[size];
    for (int i = 0; i < size; ++i) {
        err = mm_alloc(&aos_mm, 1 << 20, &retcaps[i]);
        assert(err_is_ok(err));
    }
    for (int i = 0; i < size; ++i) {
        struct capability tmp_cap;
        cap_direct_identify(retcaps[i], &tmp_cap);
        err = mm_free(&aos_mm, retcaps[i], get_address(&tmp_cap), get_size(&tmp_cap));
        assert(err_is_ok(err));
    }
    DEBUG_PRINTF("success\n");
}

__attribute__ ((unused)) static void test_map_frame_va(void) {
    errval_t err;
    uint64_t bytes = 1024;
    const uint64_t length = 64;
    for(int i = 0; i < length; i ++ ) {
        DEBUG_PRINTF("iteration %d\n", i);
        struct capref frame_cap;
        err = frame_alloc(&frame_cap, bytes, &bytes);
        assert(err_is_ok(err));
        DEBUG_PRINTF("frame: bytes: %zu\n", bytes);


        lvaddr_t vaddr = aos_mm.slabs.vaddr_new_frame;
        aos_mm.slabs.vaddr_new_frame += bytes;
        err = paging_map_fixed(get_current_paging_state(), vaddr, frame_cap, bytes);
        assert(err_is_ok(err));
        char *buf = (char *) vaddr;
        *buf = 1;
        DEBUG_PRINTF("allocated vaddr try %d at %p\n", vaddr, buf);
        DEBUG_PRINTF("value: %d\n", *buf);
    }

    DEBUG_PRINTF("success\n");
}

__attribute__ ((unused))
static void test_suite_milestone1(void) {
    test_simple_alloc_free();
    test_map_frame_va();
    test_slab_simple();
    test_handle_slot_256();
}


// ----------------------------------------------------------
// bsp_main
// ----------------------------------------------------------

static int
bsp_main(int argc, char *argv[]) {
    DEBUG_BEGIN;
    errval_t err;

    // Grading 
    grading_setup_bsp_init(argc, argv);

    // First argument contains the bootinfo location, if it's not set
    bi = (struct bootinfo *) strtol(argv[1], NULL, 10);
    assert(bi);

    err = initialize_ram_alloc();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "initialize_ram_alloc");
    }

//    test_suite_milestone1();

    // TODO: initialize mem allocator, vspace management here

    // Grading 
    grading_test_early();

    // TODO: Spawn system processes, boot second core etc. here

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

    DEBUG_END;
    return EXIT_SUCCESS;
}

static int
app_main(int argc, char *argv[]) {
    // Implement me in Milestone 5
    // Remember to call
    // - grading_setup_app_init(..);
    // - grading_test_early();
    // - grading_test_late();
    return LIB_ERR_NOT_IMPLEMENTED;
}

int main(int argc, char *argv[]) {
    DEBUG_BEGIN;
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

    DEBUG_END;
    if (my_core_id == 0) return bsp_main(argc, argv);
    else return app_main(argc, argv);
}