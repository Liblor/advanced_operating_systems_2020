#include <stdio.h>

#include <aos/aos.h>
#include <aos/debug.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>



__unused
static void simple_spawn_core1(void) {
    struct aos_rpc *rpc = aos_rpc_get_process_channel();
    errval_t err;

    const uint64_t process_number = 1;

    for(int i = 0; i < process_number; i ++) {
        char *binary_name1 = "dummy";
        domainid_t pid1;
        coreid_t core = 1;

        err = aos_rpc_process_spawn(rpc, binary_name1, core, &pid1);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "aos_rpc_process_spawn()");
            return;
        }
        debug_printf("spawned child: pid %d\n", pid1);
    }

}

int main(int argc, char *argv[])
{
    printf("Multicore test spawned\n");
    simple_spawn_core1();

    return EXIT_SUCCESS;
}
