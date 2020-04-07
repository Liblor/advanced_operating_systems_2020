#include <stdio.h>

#include <aos/aos.h>

__unused
static void lazy_alloc(void) {
    void *addr;
    size_t reserved = BASE_PAGE_SIZE * 100;
    errval_t err = paging_alloc(get_current_paging_state(),
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
static void lazy_malloc(void) {
    debug_printf("start lazy_malloc\n");
    debug_printf("malloc 256MiB\n");
    char *buf = malloc(1 << 26);

    debug_printf("write at different locations\n");
    buf[0] = 'A';
    buf[1337] = 'A';
    buf[0x1000000] = 'A';
    buf[0x3000000] = 'A';
    buf[0x395550B] = 'A';
    free(buf);
}

int main(int argc, char *argv[])
{
    printf("Faulter spawned\n");

    fail();
    return EXIT_SUCCESS;
}
