#include <aos/urpc.h>


static volatile struct urpc_shared_mem *urpc_shared_mem;
static struct bootinfo bi;

urpc_slave_spawn_process_cb urpc_slave_spawn_process = NULL;
urpc_slave_init_memsys_cb urpc_slave_init_memsys = NULL;



__unused static
errval_t dummy_slave_init_memsys(struct bootinfo *b)
{
    // TODO initialize memory system with received bootinfo
    return SYS_ERR_OK;
}

__unused static
errval_t dummy_slave_spawn_process(char *cmdline, domainid_t *ret_pid)
{
    *ret_pid = 1337;
    return SYS_ERR_OK;
}

errval_t urpc_slave_serve_req(void)
{
    assert(urpc_slave_spawn_process != NULL);
    assert(urpc_slave_init_memsys != NULL);

    errval_t err;
    while (1) {
        // wait until receive message from master
        while (urpc_shared_mem->status != UrpcMasterData) { __asm volatile("nop \n"); }

        switch (urpc_shared_mem->type) {
            case BootInfo:
                debug_printf("got BootInfo\n");

                memcpy(&bi, (void *) &urpc_shared_mem->bi, sizeof(struct bootinfo));
                err = urpc_slave_init_memsys(&bi);
                if (err_is_fail(err)) {
                    debug_printf("failed to init slave mem sys, aborting...\n");
                    return err;
                }
                urpc_shared_mem->status = UrpcEmpty;
                break;

            case SpawnRequest: {
                debug_printf("got SpawnRequest\n");
                struct urpc_spawn_request *req = (struct urpc_spawn_request *) &urpc_shared_mem->spawn_req;
                domainid_t pid;
                err = urpc_slave_spawn_process(req->args, &pid);
                debug_printf("slave_spawn_process returned: %s\n", err_getstring(err));

                struct urpc_spawn_response *resp = (struct urpc_spawn_response *) &urpc_shared_mem->spawn_resp;
                resp->newpid = pid;
                resp->err = err;
                urpc_shared_mem->type = SpawnResponse;
                urpc_shared_mem->status = UrpcSlaveData;
                break;
            }
            case SpawnResponse:
                assert(false);
                break;
            default:
                debug_printf("unknown urpc type: %p\n", urpc_shared_mem->type);
                break;
        }
    }
    return SYS_ERR_OK;
}