#include <stdio.h>

#include <aos/aos.h>
#include <aos/debug.h>
#include <aos/threads.h>
#include <aos/paging.h>
#include <aos/aos_rpc.h>
#include <grading.h>

#define NUM_CORES 2

void wait(void);
void wait(void) {
    unsigned t = 599999999;
    while (t--) { __asm__("nop"); }
}

int main(int argc, char *argv[])
{
    debug_printf("Started process-server-demo\n");
    int other_core = disp_get_core_id() % NUM_CORES;

    domainid_t pid;
    errval_t err = aos_rpc_process_spawn(aos_rpc_lmp_get_monitor_channel(), "remote-dummy", (disp_get_core_id() + 1) % NUM_CORES, &pid);
    assert(err_is_ok(err));

    debug_printf("Spawned remote-dummy on core %d\n", other_core);

    wait();
    domainid_t *pids;
    size_t pid_count;
    err = aos_rpc_process_get_all_pids(aos_rpc_lmp_get_monitor_channel(), &pids, &pid_count);
    assert(err_is_ok(err));

    printf("Running Processes:\n");
    printf("pids: %u", *pids);
    for (int i = 1; i < pid_count; i++) {
        printf(", %u", *(pids+i));
    }
    printf("\n");

    printf("Get name of pid %u:\n", *(pids+1));
    char *name;
    err = aos_rpc_process_get_name(aos_rpc_lmp_get_monitor_channel(), *(pids+1), &name);
    assert(err_is_ok(err));
    printf("%s\n", name);
    wait();

    debug_printf("Exit process-server-demo\n");
    return EXIT_SUCCESS;
}
