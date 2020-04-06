#include <stdio.h>

#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/ram_alloc.h>
#include <aos/aos_rpc.h>
#include <grading.h>
#include <spawn/spawn.h>
#include <minunit.h>
#include <mm/mm.h>
#include <collections/range_tracker.h>

#include "../../usr/init/mem_alloc.h"



// Here are some things that are not explicitly tested yet if someone has too much time.
// TODO Test mm_add() (omitted since in practice we only have the one region that is added at boot)
// TODO Test slab and slot allocator failure modes (running our of slabs/slots needs to be simulated)
// TODO Test allocating all space that is left and fill a gap that is determined by the alignment. Do that with different sizes/alignments.
// TODO Test states after free calls
// TODO Test sections 3 and 4 from the milestone1/cleopolds branch

static struct mm *test_mm;
static genpaddr_t default_region_base;
static gensize_t default_allocated;
static gensize_t default_total_size;
static struct capref caps[30000];

static int64_t count_mmnodes(struct mm *mm) {
    assert(mm != NULL);

    struct rtnode *next;
    uint64_t i = 0;
    for (next = mm->rt.head->next; next != &mm->rt.rt_tail; next = next->next) {
        i++;
    }
    return i;
}

static void check_node_count(uint64_t expected_node_count) {
    int64_t node_count = count_mmnodes(test_mm);
    mu_assert_int_eq(expected_node_count, node_count);
}

static void check_mm_valid_state(void) {
    mu_assert(test_mm->rt.head == &test_mm->rt.rt_head, "Linked list is corrupted. Head is not pointing to head node.");

    // Get last element
    struct rtnode *curr;
    struct rtnode *prev = test_mm->rt.head;

    // If this end in a unhandled pagefault or something similar fatal then the
    // tail is probably corrupted.
    for (curr = test_mm->rt.head->next; curr != &test_mm->rt.rt_tail; curr = curr->next) {
        mu_assert(prev->next == curr && curr->prev == prev, "Linked list is corrupted. Next/curr in neighboring nodes is inconsistent.");
        prev = curr;
    }
    mu_assert(curr == &test_mm->rt.rt_tail, "Linked list is corrupted. Last element is not tail node.");
}

static void check_rtnode(uint64_t n, enum range_tracker_nodetype type, uint64_t base_offset_pages, uint64_t size_pages) {
    // Get the nth node.
    struct rtnode *next;
    uint64_t i = 0;
    for (next = test_mm->rt.head->next; i < n && next != &test_mm->rt.rt_tail; next = next->next) {
        i++;
    }
    struct rtnode *node = next;

    genpaddr_t expected_base = default_region_base + base_offset_pages * BASE_PAGE_SIZE;

    mu_assert(node != &test_mm->rt.rt_tail, "Number of nodes wrong.");
    mu_assert(node->type == type, "Node type wrong.");
    mu_assert(node->base == expected_base, "Node base address wrong.");

    // size_pages == 0 can be used for the last node to indicate the "rest of the memory"
    if (size_pages != 0) {
        mu_assert(node->size == size_pages * BASE_PAGE_SIZE, "Node size wrong.");
    }
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

// Creates an alignment normalization node to normalize alignment for a test
// since default_region_base sometimes changes between runs. The node ensures
// initial alignment of alignment*BASE_PAGE_SIZE for the rest of the test.
// The node has to be freed manually at the end of the test.
static void add_alignment_normalization_node(uint64_t alignment, struct capref *retcap, size_t *retsize) {
    uint64_t default_page_count = (default_region_base + default_allocated) / BASE_PAGE_SIZE;

    uint64_t remainder = default_page_count % alignment;
    *retsize = 0;
    if (remainder != 0)
        *retsize = alignment - remainder;

    if (*retsize != 0) {
        mm_test_alloc_aligned(retcap, 1, *retsize, SYS_ERR_OK, 0);
    }
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
}

MU_TEST(test_minimal) {
    uint64_t s = default_allocated / BASE_PAGE_SIZE;
    uint64_t space = (default_total_size - default_allocated) / BASE_PAGE_SIZE;

    mm_test_alloc_aligned(&caps[0], 1, 1, SYS_ERR_OK, 3);
    check_rtnode(0, RangeTracker_NodeType_Used, 0, s);
    check_rtnode(1, RangeTracker_NodeType_Used, s + 0, 1);
    check_rtnode(2, RangeTracker_NodeType_Free, s + 1, space - 1);

    mm_test_free(caps[0], SYS_ERR_OK, 2);
}

MU_TEST(test_alignment) {
    struct capref alignment_node_cap;
    size_t alignment_node_size;
    add_alignment_normalization_node(32*3, &alignment_node_cap, &alignment_node_size);

    // One extra node from the first allocation that happens when the memory regions are added at boot.
    // One extra node if the alignment normalization node has been added.
    uint64_t n = 1 + (alignment_node_size != 0 ? 1 : 0);
    uint64_t s = alignment_node_size + default_allocated / BASE_PAGE_SIZE;
    uint64_t space = default_total_size / BASE_PAGE_SIZE;

    mm_test_alloc_aligned(&caps[0], 1, 1, SYS_ERR_OK, n+2);
    // xxxx x...x x ooo...
    check_rtnode(n+0, RangeTracker_NodeType_Used, s+0, 1);
    check_rtnode(n+1, RangeTracker_NodeType_Free, s+1, 0);

    mm_test_alloc_aligned(&caps[1], 2, 1, SYS_ERR_OK, n+4);
    // xxxx x...x x o x ooo...
    check_rtnode(n+0, RangeTracker_NodeType_Used, s+0, 1);
    check_rtnode(n+1, RangeTracker_NodeType_Free, s+1, 1);
    check_rtnode(n+2, RangeTracker_NodeType_Used, s+2, 1);
    check_rtnode(n+3, RangeTracker_NodeType_Free, s+3, 0);

    mm_test_alloc_aligned(&caps[2], 3, 1, SYS_ERR_OK, n+5);
    // xxxx x...x x o x x ooo...
    check_rtnode(n+0, RangeTracker_NodeType_Used, s+0, 1);
    check_rtnode(n+1, RangeTracker_NodeType_Free, s+1, 1);
    check_rtnode(n+2, RangeTracker_NodeType_Used, s+2, 1);
    check_rtnode(n+3, RangeTracker_NodeType_Used, s+3, 1);
    check_rtnode(n+4, RangeTracker_NodeType_Free, s+4, 0);

    mm_test_alloc_aligned(&caps[3], 3, 1, SYS_ERR_OK, n+7);
    // xxxx x...x x o x x oo x ooo...
    check_rtnode(n+0, RangeTracker_NodeType_Used, s+0, 1);
    check_rtnode(n+1, RangeTracker_NodeType_Free, s+1, 1);
    check_rtnode(n+2, RangeTracker_NodeType_Used, s+2, 1);
    check_rtnode(n+3, RangeTracker_NodeType_Used, s+3, 1);
    check_rtnode(n+4, RangeTracker_NodeType_Free, s+4, 2);
    check_rtnode(n+5, RangeTracker_NodeType_Used, s+6, 1);
    check_rtnode(n+6, RangeTracker_NodeType_Free, s+7, 0);

    mm_test_alloc_aligned(&caps[4], 4, 1, SYS_ERR_OK, n+9);
    // xxxx x...x x o x x oo x o x ooo...
    check_rtnode(n+0, RangeTracker_NodeType_Used, s+0, 1);
    check_rtnode(n+1, RangeTracker_NodeType_Free, s+1, 1);
    check_rtnode(n+2, RangeTracker_NodeType_Used, s+2, 1);
    check_rtnode(n+3, RangeTracker_NodeType_Used, s+3, 1);
    check_rtnode(n+4, RangeTracker_NodeType_Free, s+4, 2);
    check_rtnode(n+5, RangeTracker_NodeType_Used, s+6, 1);
    check_rtnode(n+6, RangeTracker_NodeType_Free, s+7, 1);
    check_rtnode(n+7, RangeTracker_NodeType_Used, s+8, 1);
    check_rtnode(n+8, RangeTracker_NodeType_Free, s+9, 0);

    mm_test_alloc_aligned(&caps[5], 4, 1, SYS_ERR_OK, n+11);
    // xxxx x...x x o x x oo x o x ooo x ooo...
    check_rtnode(n+0 , RangeTracker_NodeType_Used, s+0, 1);
    check_rtnode(n+1 , RangeTracker_NodeType_Free, s+1, 1);
    check_rtnode(n+2 , RangeTracker_NodeType_Used, s+2, 1);
    check_rtnode(n+3 , RangeTracker_NodeType_Used, s+3, 1);
    check_rtnode(n+4 , RangeTracker_NodeType_Free, s+4, 2);
    check_rtnode(n+5 , RangeTracker_NodeType_Used, s+6, 1);
    check_rtnode(n+6 , RangeTracker_NodeType_Free, s+7, 1);
    check_rtnode(n+7 , RangeTracker_NodeType_Used, s+8, 1);
    check_rtnode(n+8 , RangeTracker_NodeType_Free, s+9, 3);
    check_rtnode(n+9 , RangeTracker_NodeType_Used, s+12, 1);
    check_rtnode(n+10, RangeTracker_NodeType_Free,s+13, 0);

    mm_test_alloc_aligned(&caps[6], 4, 2, SYS_ERR_OK, n+13);
    // xxxx x...x x o x x oo x o x ooo x ooo xx ooo...
    check_rtnode(n+0 , RangeTracker_NodeType_Used, s+0, 1);
    check_rtnode(n+1 , RangeTracker_NodeType_Free, s+1, 1);
    check_rtnode(n+2 , RangeTracker_NodeType_Used, s+2, 1);
    check_rtnode(n+3 , RangeTracker_NodeType_Used, s+3, 1);
    check_rtnode(n+4 , RangeTracker_NodeType_Free, s+4, 2);
    check_rtnode(n+5 , RangeTracker_NodeType_Used, s+6, 1);
    check_rtnode(n+6 , RangeTracker_NodeType_Free, s+7, 1);
    check_rtnode(n+7 , RangeTracker_NodeType_Used, s+8, 1);
    check_rtnode(n+8 , RangeTracker_NodeType_Free, s+9, 3);
    check_rtnode(n+9 , RangeTracker_NodeType_Used, s+12, 1);
    check_rtnode(n+10, RangeTracker_NodeType_Free, s+13, 3);
    check_rtnode(n+11, RangeTracker_NodeType_Used, s+16, 2);
    check_rtnode(n+12, RangeTracker_NodeType_Free, s+18, 0);

    mm_test_alloc_aligned(&caps[7], 4, 4, SYS_ERR_OK, n+15);
    // xxxx x...x x o x x oo x o x ooo x ooo xx oo xxxx ooo...
    check_rtnode(n+0 , RangeTracker_NodeType_Used, s+0, 1);
    check_rtnode(n+1 , RangeTracker_NodeType_Free, s+1, 1);
    check_rtnode(n+2 , RangeTracker_NodeType_Used, s+2, 1);
    check_rtnode(n+3 , RangeTracker_NodeType_Used, s+3, 1);
    check_rtnode(n+4 , RangeTracker_NodeType_Free, s+4, 2);
    check_rtnode(n+5 , RangeTracker_NodeType_Used, s+6, 1);
    check_rtnode(n+6 , RangeTracker_NodeType_Free, s+7, 1);
    check_rtnode(n+7 , RangeTracker_NodeType_Used, s+8, 1);
    check_rtnode(n+8 , RangeTracker_NodeType_Free, s+9, 3);
    check_rtnode(n+9 , RangeTracker_NodeType_Used, s+12, 1);
    check_rtnode(n+10, RangeTracker_NodeType_Free, s+13, 3);
    check_rtnode(n+11, RangeTracker_NodeType_Used, s+16, 2);
    check_rtnode(n+12, RangeTracker_NodeType_Free, s+18, 2);
    check_rtnode(n+13, RangeTracker_NodeType_Used, s+20, 4);
    check_rtnode(n+14, RangeTracker_NodeType_Free, s+24, 0);

    mm_test_alloc_aligned(&caps[8], 4, 1, SYS_ERR_OK, n+16);
    // xxxx x...x x o x x oo x o x ooo x ooo xx oo xxxx x ooo...
    check_rtnode(n+0 , RangeTracker_NodeType_Used, s+0, 1);
    check_rtnode(n+1 , RangeTracker_NodeType_Free, s+1, 1);
    check_rtnode(n+2 , RangeTracker_NodeType_Used, s+2, 1);
    check_rtnode(n+3 , RangeTracker_NodeType_Used, s+3, 1);
    check_rtnode(n+4 , RangeTracker_NodeType_Free, s+4, 2);
    check_rtnode(n+5 , RangeTracker_NodeType_Used, s+6, 1);
    check_rtnode(n+6 , RangeTracker_NodeType_Free, s+7, 1);
    check_rtnode(n+7 , RangeTracker_NodeType_Used, s+8, 1);
    check_rtnode(n+8 , RangeTracker_NodeType_Free, s+9, 3);
    check_rtnode(n+9 , RangeTracker_NodeType_Used, s+12, 1);
    check_rtnode(n+10, RangeTracker_NodeType_Free, s+13, 3);
    check_rtnode(n+11, RangeTracker_NodeType_Used, s+16, 2);
    check_rtnode(n+12, RangeTracker_NodeType_Free, s+18, 2);
    check_rtnode(n+13, RangeTracker_NodeType_Used, s+20, 4);
    check_rtnode(n+14, RangeTracker_NodeType_Used, s+24, 1);
    check_rtnode(n+15, RangeTracker_NodeType_Free, s+25, 0);

    mm_test_alloc_aligned(&caps[9], 1, space-(s+25), SYS_ERR_OK, n+16);
    // xxxx x...x x o x x oo x o x ooo x ooo xx oo xxxx x x...x
    check_rtnode(n+0 , RangeTracker_NodeType_Used, s+0, 1);
    check_rtnode(n+1 , RangeTracker_NodeType_Free, s+1, 1);
    check_rtnode(n+2 , RangeTracker_NodeType_Used, s+2, 1);
    check_rtnode(n+3 , RangeTracker_NodeType_Used, s+3, 1);
    check_rtnode(n+4 , RangeTracker_NodeType_Free, s+4, 2);
    check_rtnode(n+5 , RangeTracker_NodeType_Used, s+6, 1);
    check_rtnode(n+6 , RangeTracker_NodeType_Free, s+7, 1);
    check_rtnode(n+7 , RangeTracker_NodeType_Used, s+8, 1);
    check_rtnode(n+8 , RangeTracker_NodeType_Free, s+9, 3);
    check_rtnode(n+9 , RangeTracker_NodeType_Used, s+12, 1);
    check_rtnode(n+10, RangeTracker_NodeType_Free, s+13, 3);
    check_rtnode(n+11, RangeTracker_NodeType_Used, s+16, 2);
    check_rtnode(n+12, RangeTracker_NodeType_Free, s+18, 2);
    check_rtnode(n+13, RangeTracker_NodeType_Used, s+20, 4);
    check_rtnode(n+14, RangeTracker_NodeType_Used, s+24, 1);
    check_rtnode(n+15, RangeTracker_NodeType_Used, s+25, 0);

    mm_test_alloc_aligned(&caps[10], 3, 3, SYS_ERR_OK, n+16);
    // xxxx x...x x o x x oo x o x xxx x ooo xx oo xxxx x x...x
    //            0 1 2 0 12 0 1 2 012 0 120 12 01 2012
    check_rtnode(n+0 , RangeTracker_NodeType_Used, s+0, 1);
    check_rtnode(n+1 , RangeTracker_NodeType_Free, s+1, 1);
    check_rtnode(n+2 , RangeTracker_NodeType_Used, s+2, 1);
    check_rtnode(n+3 , RangeTracker_NodeType_Used, s+3, 1);
    check_rtnode(n+4 , RangeTracker_NodeType_Free, s+4, 2);
    check_rtnode(n+5 , RangeTracker_NodeType_Used, s+6, 1);
    check_rtnode(n+6 , RangeTracker_NodeType_Free, s+7, 1);
    check_rtnode(n+7 , RangeTracker_NodeType_Used, s+8, 1);
    check_rtnode(n+8 , RangeTracker_NodeType_Used, s+9, 3);
    check_rtnode(n+9 , RangeTracker_NodeType_Used, s+12, 1);
    check_rtnode(n+10, RangeTracker_NodeType_Free, s+13, 3);
    check_rtnode(n+11, RangeTracker_NodeType_Used, s+16, 2);
    check_rtnode(n+12, RangeTracker_NodeType_Free, s+18, 2);
    check_rtnode(n+13, RangeTracker_NodeType_Used, s+20, 4);
    check_rtnode(n+14, RangeTracker_NodeType_Used, s+24, 1);
    check_rtnode(n+15, RangeTracker_NodeType_Used, s+25, 0);

    mm_test_alloc_aligned(&caps[11], 3, 3, MM_ERR_OUT_OF_MEMORY, n+16);

    for (int i = 0; i <= 10; i++) {
        mm_test_free(caps[i], SYS_ERR_OK, 0);
    }

    // Free initial alignment node
    if (alignment_node_size != 0) {
        mm_test_free(alignment_node_cap, SYS_ERR_OK, 2);
    }
}

MU_TEST(test_out_of_memory) {
    uint64_t s = default_allocated / BASE_PAGE_SIZE;
    uint64_t space = (default_total_size - default_allocated) / BASE_PAGE_SIZE;

    mm_test_alloc_aligned(&caps[1], 1, space + 1, MM_ERR_OUT_OF_MEMORY, 2);

    mm_test_alloc_aligned(&caps[2], 0x10000, space, MM_ERR_OUT_OF_MEMORY, 2);

    mm_test_alloc_aligned(&caps[3], 1, space, SYS_ERR_OK, 2);
    check_rtnode(1, RangeTracker_NodeType_Used, s+0, space);

    mm_test_free(caps[3], SYS_ERR_OK, 2);

    mm_test_alloc_aligned(&caps[4], 1, space - 1, SYS_ERR_OK, 3);
    // xxxx x...x o
    check_rtnode(1, RangeTracker_NodeType_Used, s+0, space-1);
    check_rtnode(2, RangeTracker_NodeType_Free, s+space-1, 1);

    mm_test_alloc_aligned(&caps[5], 1, 1, SYS_ERR_OK, 3);
    // xxxx x...x x
    check_rtnode(1, RangeTracker_NodeType_Used, s+0, space-1);
    check_rtnode(2, RangeTracker_NodeType_Used, s+space-1, 1);

    mm_test_alloc_aligned(&caps[6], 1, 1, MM_ERR_OUT_OF_MEMORY, 3);

    mm_test_free(caps[5], SYS_ERR_OK, 3);
    // xxxx x...x o

    mm_test_alloc_aligned(&caps[7], 1, 1, SYS_ERR_OK, 3);
    // xxxx x...x x
    check_rtnode(1, RangeTracker_NodeType_Used, s+0, space-1);
    check_rtnode(2, RangeTracker_NodeType_Used, s+space-1, 1);

    mm_test_alloc_aligned(&caps[8], 1, 1, MM_ERR_OUT_OF_MEMORY, 3);

    mm_test_free(caps[4], SYS_ERR_OK, 0);
    mm_test_free(caps[7], SYS_ERR_OK, 2);
}

MU_TEST(test_alloc_size_0) {
    mm_test_alloc_aligned(&caps[0], 1, 0, MM_ERR_INVALID_SIZE, 2);
}

MU_TEST(test_free_null) {
    mm_test_alloc_aligned(&caps[0], 1, 1, SYS_ERR_OK, 3);

    genpaddr_t base_correct = default_region_base + default_allocated;
    gensize_t size_correct = BASE_PAGE_SIZE;

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

// The functions tested here are actually not used in libmm, but they
// should still be tested somewhere
// TODO Add more extensive range tracker tests
MU_TEST(test_range_tracker_minimal) {
    errval_t err;

    struct range_tracker *rt = &test_mm->rt;

    uint64_t s = default_allocated / BASE_PAGE_SIZE;
    uint64_t space = (default_total_size - default_allocated) / BASE_PAGE_SIZE;

    uint64_t fixed_offset_pages = 0xabcd;
    uint64_t fixed_base = default_region_base + default_allocated + fixed_offset_pages * BASE_PAGE_SIZE;
    uint64_t fixed_size_pages = 10;

    struct rtnode *new_node;
    err = range_tracker_alloc_fixed(rt, fixed_base, fixed_size_pages * BASE_PAGE_SIZE, &new_node);
    mu_assert(err_no(err) == SYS_ERR_OK, "Returned error value wrong.");

    check_rtnode(0, RangeTracker_NodeType_Used, 0, s);
    check_rtnode(1, RangeTracker_NodeType_Free, s+0, fixed_offset_pages);
    check_rtnode(2, RangeTracker_NodeType_Used, s+fixed_offset_pages, fixed_size_pages);
    check_rtnode(3, RangeTracker_NodeType_Free, s+fixed_offset_pages+fixed_size_pages, space-fixed_offset_pages-fixed_size_pages);

    struct rtnode *node;
    err = range_tracker_get(rt, fixed_base, fixed_size_pages * BASE_PAGE_SIZE, &node);
    mu_assert(err_no(err) == SYS_ERR_OK, "Returned error value wrong.");
}

MU_TEST(test_alloc_stress) {
    int i, j;
    const uint64_t node_count = 1024;
    const uint64_t repetitions_multiple = 200;
    const uint64_t repetitions_single = 10000;
    assert(ARRAY_LENGTH(caps) >= node_count);

    mu_output_enabled = false;
    printf("\n");

    for (i = 0; i < repetitions_single; i++) {
        if (i % 1000 == 0) {
            debug_printf("Allocated and freed single large nodes %d times\n", i);
        }
        mm_test_alloc_aligned(&caps[0], 1, (1<<30)/BASE_PAGE_SIZE, SYS_ERR_OK, 0);
        mm_test_free(caps[0], SYS_ERR_OK, 0);
    }
    debug_printf("Allocated and freed single large nodes %d times\n", i);

    for (i = 0; i < repetitions_multiple; i++) {
        if (i % 20 == 0) {
            debug_printf("Allocated and freed %d nodes %d times\n", node_count, i);
        }
        for (j = 0; j < node_count; j++) {
            mm_test_alloc_aligned(&caps[j], 1, (1<<20)/BASE_PAGE_SIZE, SYS_ERR_OK, 0);
        }
        for (j = 0; j < node_count; j++) {
            mm_test_free(caps[j], SYS_ERR_OK, 0);
        }
    }
    debug_printf("Allocated and freed %d nodes %d times\n", node_count, i);

    for (i = 0; i < ARRAY_LENGTH(caps); i++) {
        if (i % 1000 == 0) {
            debug_printf("Allocated %d small nodes\n", i);
        }
        mm_test_alloc_aligned(&caps[i], 1, 1, SYS_ERR_OK, 0);
    }
    debug_printf("Allocated %d nodes\n", i);
    for (i = 0; i < ARRAY_LENGTH(caps); i++) {
        if (i % 1000 == 0) {
            debug_printf("Freed %d small nodes\n", i);
        }
        mm_test_free(caps[i], SYS_ERR_OK, 0);
    }
    debug_printf("Freed %d nodes\n", i);

    debug_printf("Stress test complete", i);
    mu_output_enabled = true;
}

MU_TEST_SUITE(test_suite) {
    test_mm = &aos_mm;

    // Find empty region from the bootinfo. This is the region that has been
    // added to the memory manager at boot and we need its base address and
    // size for the following tests.
    default_region_base = 0;
    for (int i = 0; i < bi->regions_length; i++) {
        if (bi->regions[i].mr_type == RegionType_Empty) {
            default_region_base = bi->regions[i].mr_base;
            default_total_size = bi->regions[i].mr_bytes;
        }
    }
    if (default_region_base == 0) {
        assert(!"No empty region found in bootinfo");
    }

    debug_printf("default_region_base=%p\n", default_region_base);

    // This is the size of the first allocation that happens when the memory
    // regions are added at boot.
    default_allocated = 4 * BASE_PAGE_SIZE;

    MU_SUITE_CONFIGURE(&test_setup, &test_teardown);

	MU_RUN_TEST(test_minimal);
	MU_RUN_TEST(test_alignment);
	MU_RUN_TEST(test_out_of_memory);
	MU_RUN_TEST(test_alloc_size_0);
	MU_RUN_TEST(test_free_null);
    // TODO This test is failing
    //MU_RUN_TEST(test_free_invalid);

    MU_RUN_TEST(test_range_tracker_minimal);

    // Leave these tests at the end
    MU_RUN_TEST(test_alloc_stress);
}


static inline void print_test_begin(const char *name)
{
    debug_printf("################################################################################\n");
    debug_printf("# Begin of test %s\n", name);
}

static inline void print_test_end(const char *name)
{
    debug_printf("End of test %s\n", name);
    debug_printf("################################################################################\n");
}

static inline void print_test_abort(const char *name)
{
    debug_printf("Aborting test %s\n", name);
    debug_printf("################################################################################\n");
}


__attribute__((__unused__))
static bool test_paging_multiple(const lvaddr_t base, lvaddr_t *newbase, const int count, const size_t size)
{
    debug_printf("test_paging_multiple(base=%"PRIxLVADDR", newbase=%p, count=%d, size=%zx)\n", base, newbase, count, size);

    errval_t err;

    *newbase = base;
    lvaddr_t vaddr = base;

    for (int i = 0; i < count; i++) {
        struct capref frame_cap;
        size_t bytes = size;

        err = frame_alloc(&frame_cap, bytes, &bytes);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "frame alloc");
            debug_printf("frame_alloc failed: %s\n", err_getstring(err));
            return false;
        }

        *newbase += bytes;

        err = paging_map_fixed_attr(get_current_paging_state(), vaddr, frame_cap, bytes, VREGION_FLAGS_READ_WRITE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "paging_map_fixed_attr");
            debug_printf("paging_map_fixed_attr failed: %s\n", err_getstring(err));
            return false;
        }

        vaddr += bytes;
    }
    for (uint32_t *buf = (uint32_t *) base; (lvaddr_t) buf < vaddr; buf++)
        *buf = 0xAAAAAAAA;

    return true;
}

__attribute__((__unused__))
static void test_paging_multi_pagetable(void) {
    print_test_begin("test_paging_multi_pagetable");

    errval_t err;
    uint64_t size = 1024 * 1024 * 1024;

    lvaddr_t *vaddr;
    lvaddr_t base;
    // MAP 1 GB
    for(int i = 0; i < 1; i ++) {
        struct capref frame_cap;
        size_t bytes = size;


        err = frame_alloc(&frame_cap, bytes, &bytes);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "frame_alloc\n");
            debug_printf("frame_alloc failed: %s\n", err_getstring(err));
            assert(false);
        }

        debug_printf("========================================\n");
        debug_printf("mapping %zu at vaddr %p\n", bytes, vaddr);
        err = paging_alloc(get_current_paging_state(), (void **) &vaddr, bytes, BASE_PAGE_SIZE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "paging_alloc failed\n");
            assert(false);
        }
        base = (lvaddr_t ) vaddr;
        err = paging_map_fixed_attr(get_current_paging_state(), base, frame_cap, bytes, VREGION_FLAGS_READ_WRITE);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "paging_map_fixed_attr failed\n");
            debug_printf("paging_map_fixed_attr failed: %s\n", err_getstring(err));
            assert(false);
        }
        for (uint32_t *buf = (uint32_t *) base; (lvaddr_t) buf < (base + bytes); buf++)
            *buf = 0xAAAAAAAA;
    }

    assert(true);
}


__attribute__((__unused__))
static void test_paging(void)
{
    const char *name = "paging";

    print_test_begin(name);

    // We may not start from VADDR_OFFSET currenty, since the
    // slab_refill_pages() function claims virtual address space starting from
    // there.

    lvaddr_t vaddr = ((lvaddr_t)512UL*1024*1024*1024 * 16); // 16GB

    bool success;

    success = test_paging_multiple(vaddr, &vaddr, 1, BASE_PAGE_SIZE);
    if (!success) {
        print_test_abort(name);
        return;
    }

    success = test_paging_multiple(vaddr, &vaddr, 1, BASE_PAGE_SIZE);
    if (!success) {
        print_test_abort(name);
        return;
    }

    success = test_paging_multiple(vaddr, &vaddr, 4, 4 * BASE_PAGE_SIZE);
    if (!success) {
        print_test_abort(name);
        return;
    }

    // For the next test to work, we need to fill the remaining L3 page
    // directory.
    success = test_paging_multiple(vaddr, &vaddr, 462, BASE_PAGE_SIZE);
    if (!success) {
        print_test_abort(name);
        return;
    }

    success = test_paging_multiple(vaddr, &vaddr, 200, 512 * BASE_PAGE_SIZE);
    if (!success) {
        print_test_abort(name);
        return;
    }

    print_test_end(name);
}

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
    //test_paging();
    //test_paging_multi_pagetable();

    MU_RUN_SUITE(test_suite);
    MU_REPORT();
}

void
grading_test_late(void) {
}
