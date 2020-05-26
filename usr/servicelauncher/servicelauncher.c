#include <aos/aos.h>
#include <aos/nameserver.h>
#include <aos/networking.h>


static void spawn_service(struct aos_rpc *proc_chan, char *executable_name)
{
    errval_t err;

    domainid_t pid;
    coreid_t core_id = 0;

    err = aos_rpc_process_spawn(proc_chan, executable_name, core_id, &pid);
    if (err_is_fail(err)) {
        debug_printf("Failed to spawn '%s': %s\n", executable_name, err_getstring(err));
        exit(EXIT_FAILURE);
    }

    debug_printf("Launched '%s' at PID %llu.\n", executable_name, pid);
}

int main(int argc, char *argv[])
{
    debug_printf("Service launcher spawned.\n");

    debug_printf("Waiting for process server...\n");
    nameservice_wait_for(NAMESERVICE_PROCESS);
    debug_printf("Process server reachable.\n");

    debug_printf("Launching services...\n");


    struct aos_rpc *proc_chan = aos_rpc_get_process_channel();

    spawn_service(proc_chan, "initserver");
    spawn_service(proc_chan, "serialserver");
    spawn_service(proc_chan, "enet");
    spawn_service(proc_chan, "blockdriverserver");

    debug_printf("Waiting for launched services...\n");
    nameservice_wait_for(NAMESERVICE_SERIAL);
    nameservice_wait_for(NAMESERVICE_INIT);

    // call grading here

    debug_printf("Spawning shell...\n");
    spawn_service(proc_chan, "aosh");

    return EXIT_SUCCESS;
}
