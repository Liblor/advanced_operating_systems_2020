#include <stdio.h>

#include <aos/aos.h>

__unused
static void lazy_alloc(void) {
    void *addr;
    size_t reserved = BASE_PAGE_SIZE * 100;
    errval_t err  = paging_alloc(get_current_paging_state(),
            &addr, reserved, BASE_PAGE_SIZE);

    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "");
    }

    lvaddr_t base = (lvaddr_t ) addr;
    for(lvaddr_t i = base; i < base + reserved; i ++) {
        *((char *) i) = 1;
    }
    debug_printf("successfully lazily reserved and fetched %d bytes of memory\n", reserved);
}



__unused
static void fail(void) {
    const char *addr = (char *) VADDR_OFFSET - BASE_PAGE_SIZE;
    printf("Byte at address %p is '%x'\n", addr, *addr);
}


__unused
static int thread_1(void *args) {
    debug_printf("hello from thread :) we attempt to fail...\n");
    __unused struct thread * thr = thread_self();
//    debug_printf("thread id: %d\n", thr->id);
//    debug_printf("thread coreid: %d\n", thr->coreid);
//    lazy_alloc();
    fail();

    return 0;
}



__unused
static void thread_test(void) {
    debug_printf("spawning thread...\n");
    __unused struct thread *t = thread_create_varstack(thread_1, NULL, 1024);
}

int main(int argc, char *argv[])
{
    printf("Faulter spawned\n");
    thread_test();

    // uncomment the line below to cause error(bug)
//    fail();





    return EXIT_SUCCESS;
}
