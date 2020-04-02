#include <stdio.h>

#include <aos/aos.h>

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

int main(int argc, char *argv[])
{
    printf("Faulter spawned\n");

    lazy_alloc();

//    fail();
    return EXIT_SUCCESS;
}
