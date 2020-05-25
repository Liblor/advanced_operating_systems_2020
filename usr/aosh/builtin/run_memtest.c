//
// Created by b on 5/25/20.
//

#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/aos_rpc_lmp_marshal.h>
#include <aos/nameserver.h>
#include <aos/deferred.h>
#include <arch/aarch64/aos/dispatcher_arch.h>


#include "run_memtest.h"


// simple read/write test of memory
static void read_write(char *addr, size_t bytes) {
    uint8_t val_start = 0;
    uint8_t val = val_start;
    printf("writing %d bytes to memory\n", bytes);
    for (int i = 0; i < bytes; i++) {
        printf("*%p = %p\n", addr + i, val);
        *(addr + i) = val;
        val = (val + 1) % 256;
    }

    val = val_start;
    printf("reading those %d bytes from memory\n", bytes);
    for (int i = 0; i < bytes; i++) {
        printf("*%p == %p\n", addr + i, *(addr + i));
        if (*(addr +i) != val) {
            printf("Error, memory at %p is not %p but %p\n", (addr +i), val, *(addr +i));
        }
        val = (val + 1) % 256;
    }
}

errval_t builtin_run_memtest(
        int argc,
        char **argv)

{
    if (argc < 2) {
        printf("Usage: %s bytes\n", argv[0]);
        printf("%s performs read write tests on virtual memory\n", argv[0]);
        return SYS_ERR_OK;
    }

    size_t bytes = atoi(argv[1]);
    char *addr = NULL;
    errval_t err = paging_alloc(get_current_paging_state(), (void **) &addr, bytes, BASE_PAGE_SIZE);
    if (err_is_fail(err)) {return err;}
    printf("\n");
    printf("obtaining virtual memory of size %d bytes at location %p\n", bytes, addr);

    struct capref frame;
    size_t ret_bytes;
    err = frame_alloc(&frame, bytes, &ret_bytes);
    if (err_is_fail(err)) {
        return err;
    }
    printf("\n");
    printf("eager mapping %d bytes at %p\n", bytes, addr);
    err = paging_map_fixed_attr(get_current_paging_state(),
                                (lvaddr_t) addr,
                                frame,
                                bytes,
                                VREGION_FLAGS_READ_WRITE);

    if (err_is_fail(err)) {return err;}

    read_write(addr, bytes);
    printf("\n");
    printf("requesting memory which pagefaults...\n");
    addr = malloc(bytes);
    read_write(addr, bytes);
    free(addr);

    printf("exiting read/write test.\n");
    return SYS_ERR_OK;


}