#include <stdio.h>

#include <aos/aos.h>
#include <aos/debug.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>



__unused
static void simple_spawn_core1(void) {
    struct aos_rpc *rpc = aos_rpc_get_process_channel();
    errval_t err;

    const uint64_t process_number = 100;

    for(int i = 0; i < process_number; i ++) {
        char *binary_name1 = "hello";
        domainid_t pid1;

        // also causing troubles
        coreid_t core = i % 2;

        err = aos_rpc_process_spawn(rpc, binary_name1, core, &pid1);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "aos_rpc_process_spawn()");
            return;
        }
        debug_printf("spawned %s: pid %d on core %i\n", binary_name1, pid1, core);
    }

}

int main(int argc, char *argv[])
{
    debug_printf("Multicore test spawned\n");
    simple_spawn_core1();

    debug_printf("Multicore test finished\n");
//    assert(false);


    return EXIT_SUCCESS;
}
