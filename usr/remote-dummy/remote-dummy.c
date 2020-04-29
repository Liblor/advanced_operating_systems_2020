#include <stdio.h>

#include <aos/aos.h>
#include <aos/debug.h>
#include <aos/threads.h>
#include <aos/paging.h>
#include <aos/aos_rpc.h>
#include <grading.h>


#define NUM_CORES 2


int main(int argc, char *argv[])
{
    debug_printf("Spawn dummy on other processor\n");
    int other_core = (disp_get_core_id() + 1) % NUM_CORES;

    domainid_t pid;
    errval_t err = aos_rpc_process_spawn(aos_rpc_lmp_get_monitor_channel(), "dummy", other_core, &pid);
    assert(err_is_ok(err));

    debug_printf("Spawned remote dummy on core %d\n", other_core);

    return EXIT_SUCCESS;
}
