
#include <stdio.h>

#include <aos/aos.h>
#include <aos/debug.h>
#include <aos/threads.h>
#include <aos/paging.h>
#include <aos/aos_rpc.h>
#include <grading.h>


#define TEST_PAGING_ALLOC_COUNT (50)
#define TEST_PAGING_ALLOC_SIZE (10 * BASE_PAGE_SIZE)
#define TEST_PAGING_MAP_FIXED_ATTR_COUNT (50)
#define TEST_PAGING_MAP_FIXED_ATTR_SIZE (10 * BASE_PAGE_SIZE)
#define TEST_PAGING_REGION_INIT_ALIGNED_COUNT (50)
#define TEST_PAGING_REGION_INIT_ALIGNED_SIZE (10 * BASE_PAGE_SIZE)
#define TEST_PAGING_REGION_MAP_COUNT (50)
#define TEST_PAGING_REGION_MAP_SIZE (10 * BASE_PAGE_SIZE)
#define TEST_PAGING_COMBINED_STAGE_COUNT (4)
#define TEST_PAGING_COMBINED_COUNT (10)

const char long_string[] = TEST_LONG_STRING;


static struct paging_state *pgst;
struct aos_rpc *init_rpc;
struct aos_rpc *mem_rpc;
struct aos_rpc *proc_rpc;
struct aos_rpc *serial_rpc;

struct thread_data_paging_combined {
    struct paging_region pr;
    void *map_fixed_buf;
    uint8_t stage;
};

static void run_threads(thread_func_t start_func, void *data)
{
    errval_t err;

    struct thread *threads[TEST_NUM_THREADS];

    for (int i = 0; i < TEST_NUM_THREADS; i++) {
        threads[i] = thread_create(start_func, data);
        assert(threads[i] != NULL);
    }

    for (int i = 0; i < TEST_NUM_THREADS; i++) {
        int retval;
        err = thread_join(threads[i], &retval);
        assert(err_is_ok(err));
    }
}

static void check_access(lvaddr_t base_addr, size_t size)
{
    for (uint8_t *buf = (uint8_t *) base_addr; (lvaddr_t) buf < base_addr + size; buf++) {
        *buf = 0x1A;
        assert(*buf == 0x1A);
    }
    // If no pagefault occurred the test is considered successful
}

static int thread_paging_alloc(void *data)
{
    errval_t err;

    void *buffers[TEST_PAGING_ALLOC_COUNT];
    memset(buffers, 0, sizeof(buffers));

    for (int i = 0; i < TEST_PAGING_ALLOC_COUNT; i++) {
        debug_printf("paging_alloc() %d/%d\n", i+1, TEST_PAGING_ALLOC_COUNT);
        void *buf;
        err = paging_alloc(pgst, &buf, TEST_PAGING_ALLOC_SIZE, BASE_PAGE_SIZE);
        assert(err_is_ok(err));
        assert(buf != NULL);
        buffers[i] = buf;
    }

    // TODO Uncomment
    /*
    for (int i = 0; i < TEST_PAGING_ALLOC_COUNT; i++) {
        err = paging_unmap(pgst, buffers[i]);
        assert(err_is_ok(err));
    }
    */

    return 0;
}

static int thread_paging_map_fixed_attr(void *data)
{
    errval_t err;

    void *buffers[TEST_PAGING_MAP_FIXED_ATTR_COUNT];
    memset(buffers, 0, sizeof(buffers));

    lvaddr_t base_offset = (lvaddr_t) data;

    uint64_t successes = 0;

    for (int i = 0; i < TEST_PAGING_MAP_FIXED_ATTR_COUNT; i++) {
        debug_printf("paging_map_fixed_attr() %d/%d\n", i+1, TEST_PAGING_MAP_FIXED_ATTR_COUNT);
        struct capref frame;
        size_t size;

        err = frame_alloc(&frame, TEST_PAGING_MAP_FIXED_ATTR_SIZE, &size);
        assert(err_is_ok(err));
        assert(size == TEST_PAGING_MAP_FIXED_ATTR_SIZE);

        lvaddr_t vaddr = base_offset + i * TEST_PAGING_MAP_FIXED_ATTR_SIZE;
        err = paging_map_fixed_attr(pgst, vaddr, frame, size, VREGION_FLAGS_READ_WRITE);
        if (err_is_ok(err)) {
            buffers[i] = (void *) vaddr;
            successes++;
        } else {
            // TODO Check how often that happens
            assert(err_no(err) == AOS_ERR_PAGING_ADDR_RESERVED);
        }
    }

    debug_printf("Successfully mapped %lu fixed addresses.\n", successes);

    debug_printf("Checking access...\n");
    for (int i = 0; i < TEST_PAGING_MAP_FIXED_ATTR_COUNT; i++) {
        if (buffers[i] != NULL) {
            check_access((lvaddr_t) buffers[i], TEST_PAGING_MAP_FIXED_ATTR_SIZE);
        }
    }

    // TODO Uncomment
    /*
    for (int i = 0; i < TEST_PAGING_MAP_FIXED_ATTR_COUNT; i++) {
        if (buffers[i] != NULL) {
            err = paging_unmap(pgst, buffers[i]);
            assert(err_is_ok(err));
        }
    }
    */

    return 0;
}

static int thread_paging_region_init_aligned(void *data)
{
    errval_t err;

    struct paging_region prs[TEST_PAGING_REGION_INIT_ALIGNED_COUNT];
    memset(prs, 0, sizeof(prs));

    for (int i = 0; i < TEST_PAGING_REGION_INIT_ALIGNED_COUNT; i++) {
        debug_printf("paging_region_init_aligned() %d/%d\n", i+1, TEST_PAGING_REGION_INIT_ALIGNED_COUNT);
        err = paging_region_init_aligned(pgst, &prs[i], TEST_PAGING_REGION_INIT_ALIGNED_SIZE, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);
        assert(err_is_ok(err));
    }

    // TODO Uncomment
    /*
    for (int i = 0; i < TEST_PAGING_REGION_INIT_ALIGNED_COUNT; i++) {
        err = paging_unmap(pgst, prs[i].node->base);
        assert(err_is_ok(err));
    }
    */

    return 0;
}

static int thread_paging_region_map(void *data)
{
    errval_t err;

    uint64_t thread_alloc_count = TEST_PAGING_REGION_MAP_COUNT / TEST_NUM_THREADS;
    struct paging_region *pr = data;
    void *buffers[thread_alloc_count];
    memset(buffers, 0, sizeof(buffers));

    for (int i = 0; i < thread_alloc_count; i++) {
        debug_printf("paging_region_map() %d/%d\n", i+1, thread_alloc_count);
        void *buf;
        size_t size;
        err = paging_region_map(pr, TEST_PAGING_REGION_MAP_SIZE, &buf, &size);
        assert(err_is_ok(err));
        assert(buf != NULL);
        assert(size == TEST_PAGING_REGION_MAP_SIZE);
        buffers[i] = buf;
    }

    debug_printf("Checking access...\n");
    for (int i = 0; i < thread_alloc_count; i++) {
        check_access((lvaddr_t) buffers[i], TEST_PAGING_REGION_MAP_SIZE);
    }

    // TODO Uncomment
    /*
    for (int i = 0; i < thread_alloc_count; i++) {
        err = paging_region_unmap(pr, (lvaddr_t) buffers[i], TEST_PAGING_REGION_MAP_SIZE);
        assert(err_is_ok(err));
    }
    */

    return 0;
}

static int thread_paging_combined(void *data)
{
    struct thread_data_paging_combined *d = data;

    // TODO If tests are added, also add them here
    for (int i = 0; i < TEST_PAGING_COMBINED_COUNT; i++) {
        assert(0 <= d->stage && d->stage <= TEST_PAGING_COMBINED_STAGE_COUNT - 1);

        debug_printf("STAGE %u (iteration %u)\n", d->stage, i+1);
        switch (d->stage) {
        case 0:
            thread_paging_alloc(NULL);
            break;
        case 1:
            thread_paging_map_fixed_attr(d->map_fixed_buf);
            break;
        case 2:
            thread_paging_region_init_aligned(NULL);
            break;
        case 3:
            thread_paging_region_map(&d->pr);
            break;
        default:
            assert(false);
            break;
        }

        d->stage++;
        d->stage %= TEST_PAGING_COMBINED_STAGE_COUNT;
    }

    return 0;
}

static int thread_aos_rpc_send_number(void *data)
{
    errval_t err;

    for (int i = 0; i < TEST_AOS_RPC_SEND_NUMBER_COUNT; i++) {
        debug_printf("aos_rpc_send_number() %d/%d\n", i+1, TEST_AOS_RPC_SEND_NUMBER_COUNT);
        err = aos_rpc_send_number(init_rpc, i);
        assert(err_is_ok(err));
    }

    return 0;
}

static int thread_aos_rpc_send_string(void *data)
{
    errval_t err;

    for (int i = 0; i < TEST_AOS_RPC_SEND_STRING_COUNT; i++) {
        debug_printf("aos_rpc_send_string() %d/%d\n", i+1, TEST_AOS_RPC_SEND_STRING_COUNT);
        err = aos_rpc_send_string(init_rpc, long_string);
        assert(err_is_ok(err));
    }

    return 0;
}

static int thread_aos_rpc_get_ram_cap(void *data)
{
    errval_t err;
    struct capref ram_caps[TEST_AOS_RPC_GET_RAM_CAP_COUNT];

    for (int i = 0; i < TEST_AOS_RPC_GET_RAM_CAP_COUNT; i++) {
        debug_printf("aos_rpc_get_ram_cap() %d/%d\n", i+1, TEST_AOS_RPC_GET_RAM_CAP_COUNT);
        size_t size;
        err = aos_rpc_get_ram_cap(mem_rpc, TEST_AOS_RPC_GET_RAM_CAP_SIZE, BASE_PAGE_SIZE, &ram_caps[i], &size);
        assert(err_is_ok(err));
        assert(size == TEST_AOS_RPC_GET_RAM_CAP_SIZE);
    }

    debug_printf("Testing RAM capabilities...\n");
    for (int i = 0; i < TEST_AOS_RPC_GET_RAM_CAP_COUNT; i++) {
        struct capref frame;

        err = slot_alloc(&frame);
        assert(err_is_ok(err));

        err = cap_retype(frame, ram_caps[i], 0, ObjType_Frame, TEST_AOS_RPC_GET_RAM_CAP_SIZE, 1);
        assert(err_is_ok(err));

        err = cap_destroy(frame);
        assert(err_is_ok(err));

        err = cap_destroy(ram_caps[i]);
        assert(err_is_ok(err));
    }

    return 0;
}

__unused
static void test_multithreading_paging_alloc(void)
{
    debug_printf("Running test_multithreading_paging_alloc()...\n");

    run_threads(thread_paging_alloc, NULL);

    debug_printf("Test done\n");
}

__unused
static void test_multithreading_paging_map_fixed_attr(void)
{
    errval_t err;

    debug_printf("Running test_multithreading_paging_map_fixed_attr()...\n");

    // Allocate one paging region for both threads to map into
    void *buf;
    err = paging_alloc(pgst, &buf, TEST_PAGING_MAP_FIXED_ATTR_COUNT * TEST_PAGING_MAP_FIXED_ATTR_SIZE , BASE_PAGE_SIZE);
    assert(err_is_ok(err));

    run_threads(thread_paging_map_fixed_attr, buf);

    debug_printf("Test done\n");
}

__unused
static void test_multithreading_paging_region_init_fixed(void)
{
    //errval_t paging_region_init_fixed(struct paging_state *st, struct paging_region *pr, lvaddr_t base, size_t size, paging_flags_t flags)
    // TODO Implement test for paging_region_init_fixed(). This should be very similar to test_multithreading_paging_region_init_aligned().
}

__unused
static void test_multithreading_paging_region_init_aligned(void)
{
    debug_printf("Running test_multithreading_paging_region_init_aligned()...\n");

    run_threads(thread_paging_region_init_aligned, NULL);

    debug_printf("Test done\n");
}

__unused
static void test_multithreading_paging_region_map(void)
{
    errval_t err;

    debug_printf("Running test_multithreading_paging_region_map()...\n");

    // Allocate one paging region for both threads to allocate from
    struct paging_region pr;
    err = paging_region_init_aligned(pgst, &pr, TEST_PAGING_REGION_MAP_COUNT * TEST_PAGING_REGION_MAP_SIZE, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);
    assert(err_is_ok(err));

    run_threads(thread_paging_region_map, &pr);

    debug_printf("Test done\n");

    // TODO Uncomment
    //err = paging_unmap(pgst, (void *) pr.node->base);
    //assert(err_is_ok(err));
}

__unused
static void test_multithreading_paging_combined(void)
{
    errval_t err;

    debug_printf("Running test_multithreading_paging_combined()...\n");

    struct thread_data_paging_combined common_data;
    err = paging_region_init_aligned(pgst, &common_data.pr, TEST_PAGING_REGION_MAP_COUNT * TEST_PAGING_REGION_MAP_SIZE, BASE_PAGE_SIZE, VREGION_FLAGS_READ_WRITE);
    assert(err_is_ok(err));
    err = paging_alloc(pgst, &common_data.map_fixed_buf, TEST_PAGING_MAP_FIXED_ATTR_COUNT * TEST_PAGING_MAP_FIXED_ATTR_SIZE , BASE_PAGE_SIZE);
    assert(err_is_ok(err));

    struct thread_data_paging_combined data[TEST_NUM_THREADS];
    struct thread *threads[TEST_NUM_THREADS];

    for (int i = 0; i < TEST_NUM_THREADS; i++) {
        memcpy(&data[i], &common_data, sizeof(data[i]));
        data[i].stage = i % TEST_PAGING_COMBINED_STAGE_COUNT;

        threads[i] = thread_create(thread_paging_combined, &data[i]);
        assert(threads[i] != NULL);
    }

    for (int i = 0; i < TEST_NUM_THREADS; i++) {
        int retval;
        err = thread_join(threads[i], &retval);
        assert(err_is_ok(err));
    }

    debug_printf("Test done\n");
}

__unused
static void test_multithreading_aos_rpc_send_number(void)
{
    debug_printf("Running test_multithreading_aos_rpc_send_number()...\n");

    run_threads(thread_aos_rpc_send_number, NULL);

    debug_printf("Test done\n");
}

__unused
static void test_multithreading_aos_rpc_send_string(void)
{
    debug_printf("Running test_multithreading_aos_rpc_send_string()...\n");

    run_threads(thread_aos_rpc_send_string, NULL);

    debug_printf("Test done\n");
}

__unused
static void test_multithreading_aos_rpc_get_ram_cap(void)
{
    debug_printf("Running test_multithreading_aos_rpc_get_ram_cap()...\n");

    run_threads(thread_aos_rpc_get_ram_cap, NULL);

    debug_printf("Test done\n");
}

__unused
static void test_multithreading_aos_rpc_serial_getchar(void)
{
//errval_t aos_rpc_serial_getchar(struct aos_rpc *chan, char *retc);
}

__unused
static void test_multithreading_aos_rpc_serial_putchar(void)
{
//errval_t aos_rpc_serial_putchar(struct aos_rpc *chan, char c);
}

__unused
static void test_multithreading_aos_rpc_process_spawn(void)
{
//errval_t aos_rpc_process_spawn(struct aos_rpc *chan, char *name, coreid_t core, domainid_t *newpid);
}

__unused
static void test_multithreading_aos_rpc_process_get_name(void)
{
//errval_t aos_rpc_process_get_name(struct aos_rpc *chan, domainid_t pid, char **name);
}

__unused
static void test_multithreading_aos_rpc_process_get_all_pids(void)
{
//errval_t aos_rpc_process_get_all_pids(struct aos_rpc *chan, domainid_t **pids, size_t *pid_count);
}


int main(int argc, char *argv[])
{
    debug_printf("Multithreading test spawned\n");

    pgst = get_current_paging_state();
    init_rpc = aos_rpc_get_init_channel();
    assert(init_rpc != NULL);
    mem_rpc = aos_rpc_get_memory_channel();
    assert(mem_rpc != NULL);
    proc_rpc = aos_rpc_get_process_channel();
    assert(proc_rpc != NULL);
    serial_rpc = aos_rpc_get_serial_channel();
    assert(serial_rpc != NULL);

    // TODO Check if tests would fail with wrong synchronization
    debug_printf("Testing multithreading capabilities of aos_rpc\n");
    test_multithreading_aos_rpc_send_number();
    test_multithreading_aos_rpc_send_string();
    test_multithreading_aos_rpc_get_ram_cap();
    test_multithreading_aos_rpc_serial_getchar();
    test_multithreading_aos_rpc_serial_putchar();
    test_multithreading_aos_rpc_process_spawn();
    test_multithreading_aos_rpc_process_get_name();
    test_multithreading_aos_rpc_process_get_all_pids();

    debug_printf("Testing multithreading capabilities of paging\n");
    test_multithreading_paging_alloc();
    test_multithreading_paging_map_fixed_attr();
    test_multithreading_paging_region_init_fixed();
    test_multithreading_paging_region_init_aligned();
    test_multithreading_paging_region_map();
    // TODO This test is failing (even with only 1 thread)
    test_multithreading_paging_combined();

    return EXIT_SUCCESS;
}
