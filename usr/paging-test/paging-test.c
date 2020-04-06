/**
 * \file
 * \brief Hello world application
 */

/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#include <stdio.h>

#include <aos/aos.h>
#include <aos/domain.h>
#include <aos/paging.h>
#include <aos/capabilities.h>


// TODO Add tests with multiple threads

// This is used to not collide with other page allocations during the tests
#define TEST_VADDR_BASE_OFFSET (VADDR_OFFSET + (1024 * 1024 * 1024)) // VADDR_OFFSET + 1GB

#define TEST_L3_TABLE_SPAN (PTABLE_SIZE + 10)
#define TEST_L2_TABLE_SPAN (PTABLE_SIZE * PTABLE_SIZE + 100) // One L2 table is 1 GB
#define TEST_PAGE_COUNT_1G ((1024 * 1024 * 1024) / BASE_PAGE_SIZE)
#define TEST_REPETITION_COUNT (1000000)
#define TEST_REGION_PAGE_COUNT (10)

static struct paging_state *test_paging_state;

static void test_check_err(errval_t err, errval_t err_expected) {
    if (err_no(err) != err_no(err_expected)) {
        debug_printf("Returned error value wrong: expected=%s (%d), actual=%s (%d)\n", err_getcode(err_expected), err_no(err_expected), err_getcode(err), err_no(err));
        abort();
    }
}

static void test_assert(bool assertion, const char *error_msg) {
    if (!assertion) {
        debug_printf("%s\n", error_msg);
        abort();
    }
}

static void check_access(lvaddr_t base_addr, size_t size) {
    // TODO Make it possible to test only read or only write
    for (uint8_t *buf = (uint8_t *) base_addr; (lvaddr_t) buf < base_addr + size; buf++)
        *buf = 0x1A;

    // If no pagefault occurred the test is considered successful
}

static void paging_test_map_fixed_attr(uint64_t base_pages, uint64_t size_pages, errval_t expected_error) {
    errval_t err;

    struct capref frame_cap;
    lvaddr_t base_addr = TEST_VADDR_BASE_OFFSET + base_pages * BASE_PAGE_SIZE;
    size_t size = size_pages * BASE_PAGE_SIZE;
    size_t retsize;

    err = frame_alloc(&frame_cap, BASE_PAGE_SIZE, &retsize);
    if (err_is_fail(err)) {
        test_assert(false, "frame_alloc() failed");
    }
    assert(size == retsize);

    err = paging_map_fixed_attr(test_paging_state, base_addr, frame_cap, size, VREGION_FLAGS_READ_WRITE);
    test_check_err(err, expected_error);

    if (err_no(err) == SYS_ERR_OK) {
        check_access(base_addr, size);
    }
}

static void paging_test_unmap(uint64_t base_pages, uint64_t size_pages, errval_t expected_error) {
    errval_t err;

    void *base_addr = (void *) (TEST_VADDR_BASE_OFFSET + base_pages * BASE_PAGE_SIZE);

    err = paging_unmap(test_paging_state, base_addr);
    test_check_err(err, expected_error);

    if (err_no(err) == SYS_ERR_OK) {
        // Check correctness of unmap by trying to map that virtual address again
        paging_test_map_fixed_attr(base_pages, size_pages, SYS_ERR_OK);

        // Undo the mapping again
        err = paging_unmap(test_paging_state, base_addr);
        test_check_err(err, SYS_ERR_OK);
    }
}

static void paging_test_region_init_fixed(struct *paging_region pr, uint64_t base_pages, uint64_t size_pages, errval_t expected_error) {
    errval_t err;

    struct capref frame_cap;
    lvaddr_t base_addr = TEST_VADDR_BASE_OFFSET + base_pages * BASE_PAGE_SIZE;
    size_t size = size_pages * BASE_PAGE_SIZE;
    size_t retsize;

    err = frame_alloc(&frame_cap, BASE_PAGE_SIZE, &retsize);
    if (err_is_fail(err)) {
        test_assert(false, "frame_alloc() failed");
    }
    assert(size == retsize);

    err = paging_region_init_fixed(test_paging_state, pr, base_addr, size, VREGION_FLAGS_READ_WRITE);
    test_check_err(err, expected_error);

    if (err_no(err) == SYS_ERR_OK) {
        check_access(base_addr, size);
    }
}

__attribute__((__unused__))
static void test_paging_minimal(void) {
    paging_test_map_fixed_attr(0, 1, SYS_ERR_OK);
    paging_test_unmap(0, 1, SYS_ERR_OK);
}

__attribute__((__unused__))
static void test_paging_l3_span_single(void) {
    paging_test_map_fixed_attr(0, TEST_L3_TABLE_SPAN, SYS_ERR_OK);
    paging_test_unmap(0, TEST_L3_TABLE_SPAN, SYS_ERR_OK);
}

__attribute__((__unused__))
static void test_paging_l3_span_multiple(void) {
    for (uint64_t i = 0; i < TEST_L3_TABLE_SPAN; i++) {
        paging_test_map_fixed_attr(i, 1, SYS_ERR_OK);
    }

    for (uint64_t i = 0; i < TEST_L3_TABLE_SPAN; i++) {
        paging_test_unmap(i, 1, SYS_ERR_OK);
    }
}

__attribute__((__unused__))
static void test_paging_errors(void) {
    // Overlap checks
    paging_test_unmap(0, 1, SYS_ERR_OK); // TODO Set error
    paging_test_map_fixed_attr(0, 1, SYS_ERR_OK);
    paging_test_map_fixed_attr(0, 1, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED);
    paging_test_unmap(0, 1, SYS_ERR_OK);

    // Spanning an L3 table
    paging_test_map_fixed_attr(1024, TEST_L3_TABLE_SPAN, SYS_ERR_OK);
    paging_test_map_fixed_attr(1024, TEST_L3_TABLE_SPAN, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED);
    paging_test_map_fixed_attr(1024, 1, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED);
    paging_test_map_fixed_attr(1024 + TEST_L3_TABLE_SPAN - 1, 1, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED);
    paging_test_map_fixed_attr(1024 + TEST_L3_TABLE_SPAN/2, TEST_L3_TABLE_SPAN, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED);
    paging_test_map_fixed_attr(1024 - TEST_L3_TABLE_SPAN/2, TEST_L3_TABLE_SPAN, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED);
    paging_test_map_fixed_attr(1023, 1, SYS_ERR_OK);
    paging_test_map_fixed_attr(1024 + TEST_L3_TABLE_SPAN, 1, SYS_ERR_OK);

    paging_test_unmap(1024, TEST_L3_TABLE_SPAN, SYS_ERR_OK);
    paging_test_unmap(1023, 1, SYS_ERR_OK);
    paging_test_unmap(1024 + TEST_L3_TABLE_SPAN, 1, SYS_ERR_OK);

    // TODO Test more errors
}

__attribute__((__unused__))
static void test_paging_regions(void) {
    errval_t err;

    struct paging_region pr;

    paging_test_region_init_fixed(&pr, 0, TEST_REGION_PAGE_COUNT, SYS_ERR_OK);
    paging_test_region_init_fixed(&pr, 0, TEST_REGION_PAGE_COUNT, SYS_ERR_OK); // TODO Set error

    // TODO Test functionality of paging regions
    //err = paging_region_map(struct paging_region *pr, size_t req_size, void **retbuf, size_t *ret_size);
    //err = paging_region_unmap(struct paging_region *pr, lvaddr_t base, size_t bytes);

    paging_test_unmap(0, TEST_REGION_PAGE_COUNT, SYS_ERR_OK);
    paging_test_unmap(0, TEST_REGION_PAGE_COUNT, SYS_ERR_OK); // TODO Set error

}

__attribute__((__unused__))
static void test_paging_regions_errors(void) {
    struct paging_region pr;

    paging_test_unmap(0, 1, SYS_ERR_OK); // TODO Set error

    // Overlap checks
    paging_test_region_init_fixed(&pr, 0, 1, SYS_ERR_OK);
    paging_test_region_init_fixed(&pr, 0, 1, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED); // TODO Set error
    paging_test_unmap(0, 1, SYS_ERR_OK);

    // Spanning an L3 table
    paging_test_region_init_fixed(&pr, 1024, TEST_L3_TABLE_SPAN, SYS_ERR_OK);
    paging_test_region_init_fixed(&pr, 1024, TEST_L3_TABLE_SPAN, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED); // TODO Set error
    paging_test_region_init_fixed(&pr, 1024, 1, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED); // TODO Set error
    paging_test_region_init_fixed(&pr, 1024 + TEST_L3_TABLE_SPAN - 1, 1, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED); // TODO Set error
    paging_test_region_init_fixed(&pr, 1024 + TEST_L3_TABLE_SPAN/2, TEST_L3_TABLE_SPAN, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED); // TODO Set error
    paging_test_region_init_fixed(&pr, 1024 - TEST_L3_TABLE_SPAN/2, TEST_L3_TABLE_SPAN, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED); // TODO Set error
    paging_test_region_init_fixed(&pr, 1023, 1, SYS_ERR_OK);
    paging_test_region_init_fixed(&pr, 1024 + TEST_L3_TABLE_SPAN, 1, SYS_ERR_OK);

    paging_test_unmap(1023, 1, SYS_ERR_OK);
    paging_test_unmap(1024 + TEST_L3_TABLE_SPAN, 1, SYS_ERR_OK);

    // Make sure the regions cannot be occupied by common mappings either
    paging_test_map_fixed_attr(1024, TEST_L3_TABLE_SPAN, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED);
    paging_test_map_fixed_attr(1024, 1, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED);
    paging_test_map_fixed_attr(1024 + TEST_L3_TABLE_SPAN - 1, 1, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED);
    paging_test_map_fixed_attr(1024 + TEST_L3_TABLE_SPAN/2, TEST_L3_TABLE_SPAN, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED);
    paging_test_map_fixed_attr(1024 - TEST_L3_TABLE_SPAN/2, TEST_L3_TABLE_SPAN, LIB_ERR_PAGING_ADDR_ALREADY_MAPPED);
    paging_test_map_fixed_attr(1023, 1, SYS_ERR_OK);
    paging_test_map_fixed_attr(1024 + TEST_L3_TABLE_SPAN, 1, SYS_ERR_OK);

    paging_test_unmap(1023, 1, SYS_ERR_OK);
    paging_test_unmap(1024 + TEST_L3_TABLE_SPAN, 1, SYS_ERR_OK);


    paging_test_unmap(1024, TEST_L3_TABLE_SPAN, SYS_ERR_OK);
}

__attribute__((__unused__))
static void test_paging_1g_single(void) {
    paging_test_map_fixed_attr(0, TEST_PAGE_COUNT_1G, SYS_ERR_OK);
    paging_test_unmap(0, TEST_PAGE_COUNT_1G, SYS_ERR_OK);
}

__attribute__((__unused__))
static void test_paging_1g_multiple(void) {
    for (uint64_t i = 0; i < TEST_PAGE_COUNT_1G; i++) {
        paging_test_map_fixed_attr(i, 1, SYS_ERR_OK);
    }

    for (uint64_t i = 0; i < TEST_PAGE_COUNT_1G; i++) {
        paging_test_unmap(i, 1, SYS_ERR_OK);
    }
}

__attribute__((__unused__))
static void test_paging_more_than_1g_single(void) {
    paging_test_map_fixed_attr(0, TEST_L2_TABLE_SPAN, SYS_ERR_OK);
    paging_test_unmap(0, TEST_L2_TABLE_SPAN, SYS_ERR_OK);
}

__attribute__((__unused__))
static void test_paging_repetition(void) {
    for (uint64_t i = 0; i < TEST_REPETITION_COUNT; i++) {
        paging_test_map_fixed_attr(i, 1, SYS_ERR_OK);
        paging_test_unmap(i, 1, SYS_ERR_OK);
    }
}

__attribute__((__unused__))
static void test_paging_stress(void) {
}

static void test_paging(void) {
    debug_printf("Testing paging...\n");

    test_paging_state = get_current_paging_state();

    test_paging_minimal();
    test_paging_l3_span_single();
    test_paging_l3_span_multiple();
    test_paging_errors();
    test_paging_regions();
    test_paging_regions_errors();
    test_paging_1g_single();
    test_paging_1g_multiple();
    test_paging_repetition();
    test_paging_stress();
}

int main(int argc, char *argv[])
{
    test_paging();

    return EXIT_SUCCESS;
}
