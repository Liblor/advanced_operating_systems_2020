#include <stdio.h>

#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/ram_alloc.h>
#include <aos/aos_rpc.h>
#include <grading.h>
#include <spawn/spawn.h>
#include <minunit.h>
#include <mm/mm.h>

#include "../../usr/init/mem_alloc.h"



static struct mm *test_mm;
static genpaddr_t default_region_base;
static gensize_t default_allocated;
static gensize_t default_total_size;
static struct capref caps[1000];

static int64_t count_mmnodes(struct mm *mm) {
    assert(mm != NULL);

    struct mmnode *next;
    uint64_t i = 0;
    for (next = mm->head->next; next != &mm->mm_tail; next = next->next) {
        i++;
    }
    return i;
}

static void check_node_count(uint64_t expected_node_count) {
    int64_t node_count = count_mmnodes(test_mm);
    mu_assert_int_eq(expected_node_count, node_count);
}

static void check_mm_valid_state(void) {
    mu_assert(test_mm->head == &test_mm->mm_head, "Linked list is corrupted. Head is not pointing to head node.");

    // Get last element
    struct mmnode *curr;
    struct mmnode *prev = test_mm->head;

    // If this end in a unhandled pagefault or something similar fatal then the
    // tail is probably corrupted.
    for (curr = test_mm->head->next; curr != &test_mm->mm_tail; curr = curr->next) {
        mu_assert(prev->next == curr && curr->prev == prev, "Linked list is corrupted. Next/curr in neighboring nodes is inconsistent.");
        prev = curr;
    }
    mu_assert(curr == &test_mm->mm_tail, "Linked list is corrupted. Last element is not tail node.");
}

static void check_mmnode(uint64_t n, enum nodetype type, uint64_t base_offset_pages, uint64_t size_pages) {
    // Get the nth node.
    struct mmnode *next;
    uint64_t i = 0;
    for (next = test_mm->head->next; i < n && next != &test_mm->mm_tail; next = next->next) {
        i++;
    }
    struct mmnode *node = next;

    genpaddr_t expected_base = default_region_base + base_offset_pages * BASE_PAGE_SIZE;

    mu_assert(node != &test_mm->mm_tail, "Number of nodes wrong.");
    mu_assert(node->type == type, "Node type wrong.");
    mu_assert(node->base == expected_base, "Node base address wrong.");

    // size_pages == 0 can be used for the last node to indicate the "rest of the memory"
    // TODO Maybe make it possible to check that size as well, but I think the values need to be calculated manually.
    if (size_pages != 0) {
        mu_assert(node->size == size_pages * BASE_PAGE_SIZE, "Node size wrong.");
    }

    // TODO check capinfo for consistency and with cap_direct_identify()?
}

static void mm_test_alloc_aligned(struct capref *retcap, uint64_t alignment_pages, uint64_t size_pages, errval_t expected_error, uint64_t expected_node_count) {
    int64_t node_count_before = count_mmnodes(test_mm);
    errval_t err = mm_alloc_aligned(test_mm, size_pages * BASE_PAGE_SIZE, alignment_pages * BASE_PAGE_SIZE, retcap);
    int64_t node_count_after = count_mmnodes(test_mm);

    check_mm_valid_state();

    if (err_no(err) != err_no(expected_error)) {
        debug_printf("expected=%s (%d), actual=%s (%d)\n", err_getcode(expected_error), expected_error, err_getcode(err), err);
    }
    mu_assert(err_no(err) == err_no(expected_error), "Returned error value wrong.");

    if (err != SYS_ERR_OK) {
        mu_assert(capref_is_null(*retcap), "Capability was given despite error.");
        mu_assert(node_count_before == node_count_after, "Node count has changes despite error.");
    }

    if (expected_node_count != 0) {
        check_node_count(expected_node_count);
    }
}

static void _mm_test_free(struct capref cap, genpaddr_t base, gensize_t size, errval_t expected_error, uint64_t expected_node_count) {
    errval_t err;

    int64_t node_count_before = count_mmnodes(test_mm);
    err = mm_free(test_mm, cap, base, size);
    int64_t node_count_after = count_mmnodes(test_mm);

    check_mm_valid_state();

    if (err_no(err) != err_no(expected_error)) {
        debug_printf("expected=%s, actual=%s\n", err_getcode(expected_error), err_getcode(err));
    }
    mu_assert(err_no(err) == err_no(expected_error), "Returned error value wrong.");

    if (err != SYS_ERR_OK) {
        mu_assert(node_count_before == node_count_after, "Node count has changes despite error.");
    }

    if (expected_node_count != 0) {
        check_node_count(expected_node_count);
    }
}

static void mm_test_free(struct capref cap, errval_t expected_error, uint64_t expected_node_count) {
    errval_t err;
    struct capability capability;

    err = cap_direct_identify(cap, &capability);
    if (err_is_fail(err)) {
        assert(!"cap_direct_identify failed, something is probably wrong with your tests.");
    }

    genpaddr_t base = get_address(&capability);
    gensize_t size = get_size(&capability);

    _mm_test_free(cap, base, size, expected_error, expected_node_count);
}

static void test_setup(void) {
    // Ensure that all caps are NULL_CAP when a test starts. This guarantee is
    // used during the test for checking if mm_alloc() didn't wrongly give out
    // a capability.
    for (int i = 0; i < ARRAY_LENGTH(caps); i++) {
        caps[i] = NULL_CAP;
    }
}

static void test_teardown(void) {
    // Make sure each test leaves a clean memory manager
    assert(count_mmnodes(test_mm) == 2);
}

MU_TEST(test_minimal) {
    uint64_t s = default_allocated / BASE_PAGE_SIZE;

    mm_test_alloc_aligned(&caps[0], 1, 1, SYS_ERR_OK, 3);
    check_mmnode(0, NodeType_Allocated, 0, s);
    check_mmnode(1, NodeType_Allocated, s + 0, 1);

    mm_test_free(caps[0], SYS_ERR_OK, 2);
}

MU_TEST(test_alignment) {
    // Add alignment normalization node to normalize alignment for this test
    // since default_region_base sometimes changes between runs. The node
    // ensures initial alignment of 32*3*BASE_PAGE_SIZE for the rest of the test.
    uint64_t default_page_count = (default_region_base + default_allocated) / BASE_PAGE_SIZE;

    uint64_t alignment = 32 * 3;
    uint64_t remainder = default_page_count % alignment;
    size_t alignment_node_size = 0;
    if (remainder != 0)
        alignment_node_size = alignment - remainder;

    struct capref alignment_node_cap;
    if (alignment_node_size != 0) {
        mm_test_alloc_aligned(&alignment_node_cap, 1, alignment_node_size, SYS_ERR_OK, 0);
    }

    // One extra node from the first allocation that happens when the memory regions are added at boot.
    // One extra node if the alignment normalization node has been added.
    uint64_t n = 1 + (alignment_node_size != 0 ? 1 : 0);
    uint64_t s = alignment_node_size + default_allocated / BASE_PAGE_SIZE;

    mm_test_alloc_aligned(&caps[0], 1, 1, SYS_ERR_OK, n+2);
    // xxxx x...x x ooo...
    check_mmnode(n+0, NodeType_Allocated, s+0, 1);
    check_mmnode(n+1, NodeType_Free,      s+1, 0);

    mm_test_alloc_aligned(&caps[1], 2, 1, SYS_ERR_OK, n+4);
    // xxxx x...x x o x ooo...
    check_mmnode(n+0, NodeType_Allocated, s+0, 1);
    check_mmnode(n+1, NodeType_Free,      s+1, 1);
    check_mmnode(n+2, NodeType_Allocated, s+2, 1);
    check_mmnode(n+3, NodeType_Free,      s+3, 0);

    mm_test_alloc_aligned(&caps[2], 3, 1, SYS_ERR_OK, n+5);
    // xxxx x...x x o x x ooo...
    check_mmnode(n+0, NodeType_Allocated, s+0, 1);
    check_mmnode(n+1, NodeType_Free,      s+1, 1);
    check_mmnode(n+2, NodeType_Allocated, s+2, 1);
    check_mmnode(n+3, NodeType_Allocated, s+3, 1);
    check_mmnode(n+4, NodeType_Free,      s+4, 0);

    mm_test_alloc_aligned(&caps[3], 3, 1, SYS_ERR_OK, n+7);
    // xxxx x...x x o x x oo x ooo...
    check_mmnode(n+0, NodeType_Allocated, s+0, 1);
    check_mmnode(n+1, NodeType_Free,      s+1, 1);
    check_mmnode(n+2, NodeType_Allocated, s+2, 1);
    check_mmnode(n+3, NodeType_Allocated, s+3, 1);
    check_mmnode(n+4, NodeType_Free,      s+4, 2);
    check_mmnode(n+5, NodeType_Allocated, s+6, 1);
    check_mmnode(n+6, NodeType_Free,      s+7, 0);

    mm_test_alloc_aligned(&caps[4], 4, 1, SYS_ERR_OK, n+9);
    // xxxx x...x x o x x oo x o x ooo...
    check_mmnode(n+0, NodeType_Allocated, s+0, 1);
    check_mmnode(n+1, NodeType_Free,      s+1, 1);
    check_mmnode(n+2, NodeType_Allocated, s+2, 1);
    check_mmnode(n+3, NodeType_Allocated, s+3, 1);
    check_mmnode(n+4, NodeType_Free,      s+4, 2);
    check_mmnode(n+5, NodeType_Allocated, s+6, 1);
    check_mmnode(n+6, NodeType_Free,      s+7, 1);
    check_mmnode(n+7, NodeType_Allocated, s+8, 1);
    check_mmnode(n+8, NodeType_Free,      s+9, 0);

    mm_test_alloc_aligned(&caps[5], 4, 1, SYS_ERR_OK, n+11);
    // xxxx x...x x o x x oo x o x ooo x ooo...
    check_mmnode(n+0 , NodeType_Allocated, s+0, 1);
    check_mmnode(n+1 , NodeType_Free,      s+1, 1);
    check_mmnode(n+2 , NodeType_Allocated, s+2, 1);
    check_mmnode(n+3 , NodeType_Allocated, s+3, 1);
    check_mmnode(n+4 , NodeType_Free,      s+4, 2);
    check_mmnode(n+5 , NodeType_Allocated, s+6, 1);
    check_mmnode(n+6 , NodeType_Free,      s+7, 1);
    check_mmnode(n+7 , NodeType_Allocated, s+8, 1);
    check_mmnode(n+8 , NodeType_Free,      s+9, 3);
    check_mmnode(n+9 , NodeType_Allocated, s+12, 1);
    check_mmnode(n+10, NodeType_Free,     s+13, 0);

    mm_test_alloc_aligned(&caps[6], 4, 2, SYS_ERR_OK, n+13);
    // xxxx x...x x o x x oo x o x ooo x ooo xx ooo...
    check_mmnode(n+0 , NodeType_Allocated, s+0, 1);
    check_mmnode(n+1 , NodeType_Free,      s+1, 1);
    check_mmnode(n+2 , NodeType_Allocated, s+2, 1);
    check_mmnode(n+3 , NodeType_Allocated, s+3, 1);
    check_mmnode(n+4 , NodeType_Free,      s+4, 2);
    check_mmnode(n+5 , NodeType_Allocated, s+6, 1);
    check_mmnode(n+6 , NodeType_Free,      s+7, 1);
    check_mmnode(n+7 , NodeType_Allocated, s+8, 1);
    check_mmnode(n+8 , NodeType_Free,      s+9, 3);
    check_mmnode(n+9 , NodeType_Allocated, s+12, 1);
    check_mmnode(n+10, NodeType_Free,      s+13, 3);
    check_mmnode(n+11, NodeType_Allocated, s+16, 2);
    check_mmnode(n+12, NodeType_Free,      s+18, 0);

    mm_test_alloc_aligned(&caps[7], 4, 4, SYS_ERR_OK, n+15);
    // xxxx x...x x o x x oo x o x ooo x ooo xx oo xxxx ooo...
    check_mmnode(n+0 , NodeType_Allocated, s+0, 1);
    check_mmnode(n+1 , NodeType_Free,      s+1, 1);
    check_mmnode(n+2 , NodeType_Allocated, s+2, 1);
    check_mmnode(n+3 , NodeType_Allocated, s+3, 1);
    check_mmnode(n+4 , NodeType_Free,      s+4, 2);
    check_mmnode(n+5 , NodeType_Allocated, s+6, 1);
    check_mmnode(n+6 , NodeType_Free,      s+7, 1);
    check_mmnode(n+7 , NodeType_Allocated, s+8, 1);
    check_mmnode(n+8 , NodeType_Free,      s+9, 3);
    check_mmnode(n+9 , NodeType_Allocated, s+12, 1);
    check_mmnode(n+10, NodeType_Free,      s+13, 3);
    check_mmnode(n+11, NodeType_Allocated, s+16, 2);
    check_mmnode(n+12, NodeType_Free,      s+18, 2);
    check_mmnode(n+13, NodeType_Allocated, s+20, 4);
    check_mmnode(n+14, NodeType_Free,      s+24, 0);

    mm_test_alloc_aligned(&caps[8], 4, 1, SYS_ERR_OK, n+16);
    // xxxx x...x x o x x oo x o x ooo x ooo xx oo xxxx x ooo...
    check_mmnode(n+0 , NodeType_Allocated, s+0, 1);
    check_mmnode(n+1 , NodeType_Free,      s+1, 1);
    check_mmnode(n+2 , NodeType_Allocated, s+2, 1);
    check_mmnode(n+3 , NodeType_Allocated, s+3, 1);
    check_mmnode(n+4 , NodeType_Free,      s+4, 2);
    check_mmnode(n+5 , NodeType_Allocated, s+6, 1);
    check_mmnode(n+6 , NodeType_Free,      s+7, 1);
    check_mmnode(n+7 , NodeType_Allocated, s+8, 1);
    check_mmnode(n+8 , NodeType_Free,      s+9, 3);
    check_mmnode(n+9 , NodeType_Allocated, s+12, 1);
    check_mmnode(n+10, NodeType_Free,      s+13, 3);
    check_mmnode(n+11, NodeType_Allocated, s+16, 2);
    check_mmnode(n+12, NodeType_Free,      s+18, 2);
    check_mmnode(n+13, NodeType_Allocated, s+20, 4);
    check_mmnode(n+14, NodeType_Allocated, s+24, 1);
    check_mmnode(n+15, NodeType_Free,      s+25, 0);

    // TODO Allocate all space that is left and fill a gap that is determined by the alignment
    // TODO Do that with different sizes/alignments

    for (int i = 0; i < 9; i++) {
        mm_test_free(caps[i], SYS_ERR_OK, 0);
    }

    // Free initial alignment node
    if (alignment_node_size != 0) {
        mm_test_free(alignment_node_cap, SYS_ERR_OK, 2);
    }
}

MU_TEST(test_out_of_memory) {
    uint64_t s = default_allocated / BASE_PAGE_SIZE;
    uint64_t space = default_total_size / BASE_PAGE_SIZE;

    mm_test_alloc_aligned(&caps[1], 1, space + 1, MM_ERR_OUT_OF_MEMORY, 2);

    // TODO This test could fail by chance because of the inconsistent alignment of the boot region. Insert an alignment normalization node to be sure.
    mm_test_alloc_aligned(&caps[2], 2000, space, MM_ERR_OUT_OF_MEMORY, 2);

    mm_test_alloc_aligned(&caps[3], 1, space, SYS_ERR_OK, 2);
    check_mmnode(1, NodeType_Allocated, s+0, space);

    mm_test_free(caps[3], SYS_ERR_OK, 2);

    mm_test_alloc_aligned(&caps[4], 1, space - 1, SYS_ERR_OK, 3);
    // xxxx x...x o
    check_mmnode(1, NodeType_Allocated, s+0, space-1);
    check_mmnode(2, NodeType_Free, s+space-1, 1);

    mm_test_alloc_aligned(&caps[5], 1, 1, SYS_ERR_OK, 3);
    // xxxx x...x x
    check_mmnode(1, NodeType_Allocated, s+0, space-1);
    check_mmnode(2, NodeType_Allocated, s+space-1, 1);

    mm_test_alloc_aligned(&caps[6], 1, 1, MM_ERR_OUT_OF_MEMORY, 3);

    mm_test_free(caps[5], SYS_ERR_OK, 3);
    // xxxx x...x o

    mm_test_alloc_aligned(&caps[7], 1, 1, SYS_ERR_OK, 3);
    // xxxx x...x x
    check_mmnode(1, NodeType_Allocated, s+0, space-1);
    check_mmnode(2, NodeType_Allocated, s+space-1, 1);

    mm_test_alloc_aligned(&caps[8], 1, 1, MM_ERR_OUT_OF_MEMORY, 3);

    mm_test_free(caps[4], SYS_ERR_OK, 0);
    mm_test_free(caps[7], SYS_ERR_OK, 0);
}

// TODO Check all other possible errors
MU_TEST(test_alloc_size_0) {
    mm_test_alloc_aligned(&caps[0], 1, 0, MM_ERR_INVALID_SIZE, 2);
}

MU_TEST(test_free_null) {
    mm_test_alloc_aligned(&caps[0], 1, 1, SYS_ERR_OK, 3);

    genpaddr_t base_correct = default_region_base + default_allocated;
    gensize_t size_correct = BASE_PAGE_SIZE;

    // TODO Maybe use an explicit error for NULL_CAP.
    _mm_test_free(NULL_CAP, base_correct, size_correct, LIB_ERR_CAP_DELETE, 3);

    _mm_test_free(caps[0], base_correct, size_correct, SYS_ERR_OK, 2);
}

MU_TEST(test_free_invalid) {
    mm_test_alloc_aligned(&caps[0], 1, 1, SYS_ERR_OK, 3);

    genpaddr_t base_correct = default_region_base + default_allocated;
    gensize_t size_correct = BASE_PAGE_SIZE;

    _mm_test_free(caps[0], base_correct+1, size_correct, MM_ERR_NOT_FOUND, 3);

    _mm_test_free(caps[0], base_correct, size_correct+1, MM_ERR_NOT_FOUND, 3);

    _mm_test_free(caps[0], base_correct, size_correct, SYS_ERR_OK, 2);
}

MU_TEST_SUITE(test_suite) {
    test_mm = &aos_mm;

    // This is the base address of the first and only region added to the
    // memory manager at boot.
    default_region_base = bi->regions[4].mr_base;
    debug_printf("default_region_base=%p\n", default_region_base);

    // This is the size of the first allocation that happens when the memory
    // regions are added at boot.
    default_allocated = 4 * BASE_PAGE_SIZE;

    // This is the amount of free memory that is left after the memory
    // initialization at boot.
    default_total_size = bi->regions[4].mr_bytes - default_allocated;

    MU_SUITE_CONFIGURE(&test_setup, &test_teardown);

	MU_RUN_TEST(test_minimal);
	MU_RUN_TEST(test_alignment);
	MU_RUN_TEST(test_out_of_memory);
	MU_RUN_TEST(test_alloc_size_0);
	MU_RUN_TEST(test_free_null);
    MU_RUN_TEST(test_free_invalid);
}


// TODO Test allocating more than 256 slots with test_mm.slot_alloc and then freeing them with slot_free
// TODO Test allocating 512 pieces of memory (size 1 << 20) and then freeing them
// TODO Test allocating and immediately freeing 1024 pieces of memory (size 1 << 30) and then freeing them
// TODO Add these types of test as well.
/*
    debug_printf("########################### SECTION 3 ############################\n");

    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4096*16, &caps[0], true, false);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, space - 4096*16, &caps[1], true, false);
    mm_test_free(mm, caps[0], true, false);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4096*4, &caps[2], true, false);
    mm_test_free(mm, caps[2], true, false);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE*5, 4096*16, &caps[3], false, false);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE*5, 4096, &caps[4], true, false);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4096, &caps[5], true, false);
    mm_test_free(mm, caps[4], true, false);
    mm_test_free(mm, caps[1], true, false);
    mm_test_free(mm, caps[5], true, false);

    debug_printf("########################### SECTION 4 ############################\n");
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4096*16, &caps[0], true, false);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, space - 4096*16, &caps[1], true, false);
    mm_test_free(mm, caps[0], true, false);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4096*16, &caps[2], true, false);
    mm_test_free(mm, caps[2], true, false);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4096*8, &caps[3], true, false);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4096*8, &caps[4], true, false);
    mm_test_free(mm, caps[3], true, false);
    mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4096*8, &caps[5], true, false);
    mm_test_free(mm, caps[4], true, false);
    mm_test_free(mm, caps[5], true, false);
    mm_test_free(mm, caps[1], true, false);

    debug_printf("########################### SECTION 6 ############################\n");
    for (int j = 1; j <= 100; j++) {
        if (j % 10 == 0)
            debug_printf("Iteration %u\n", j);
        for (int i = 0; i < ARRAY_LENGTH(caps); i++) {
            mm_test_alloc_aligned(mm, BASE_PAGE_SIZE, 4096, &caps[i], true, true);
        }
        for (int i = 0; i < ARRAY_LENGTH(caps); i++) {
            mm_test_free(mm, caps[i], true, true);
        }
    }

    debug_printf("######################### TEST COMPLETED #########################\n");
*/

void
grading_setup_bsp_init(int argc, char **argv) {
}

void
grading_setup_app_init(struct bootinfo *bootinfo) {
}

void
grading_setup_noninit(int *argc, char ***argv) {
}

void
grading_test_mm(struct mm * test) {
}

void
grading_test_early(void) {

    MU_RUN_SUITE(test_suite);
    MU_REPORT();

    //return MU_EXIT_CODE;
}

void
grading_test_late(void) {
}
