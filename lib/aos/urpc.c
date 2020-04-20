#include <aos/aos.h>
#include <aos/urpc.h>

static volatile struct urpc_shared_mem *urpc_shared_mem;

errval_t urpc_init(void)
{
    errval_t err;
    size_t urpc_frame_size;
    err = frame_alloc(&cap_urpc, URPC_SHARED_MEM_SIZE, &urpc_frame_size);
    if (err_is_fail(err)) {
        debug_printf("frame alloc for urpc failed: %s\n", err_getstring(err));
        return err;
    }
    err = paging_map_frame(
            get_current_paging_state(),
            (void **) &urpc_shared_mem,
            URPC_SHARED_MEM_SIZE,
            cap_urpc,
            0,
            0
    );
    if (err_is_fail(err)) {
        debug_printf("frame alloc for urpc failed: %s\n", err_getstring(err));
        return err;
    }
    urpc_shared_mem->status = UrpcEmpty;

    return SYS_ERR_OK;
}

errval_t urpc_send_boot_info(struct bootinfo *bi)
{
    // TODO: Barriers?
    while (urpc_shared_mem->status != UrpcEmpty);
    urpc_shared_mem->status = UrpcWritting;
    urpc_shared_mem->type = BootInfo;
    urpc_shared_mem->bi = *bi;
    urpc_shared_mem->status = UrpcMasterData;
    return SYS_ERR_OK;
}

errval_t urpc_send_spawn_request(
        char *cmdline,
        coreid_t core,
        domainid_t *newpid
) {
    // TODO: Barriers?
    while (urpc_shared_mem->status != UrpcEmpty);
    urpc_shared_mem->status = UrpcWritting;
    urpc_shared_mem->type = SpawnRequest;
    size_t cmdline_size = strlen(cmdline) + 1;
    if (cmdline_size > URPC_SHARED_MEM_SIZE - sizeof(struct urpc_shared_mem)) {
        urpc_shared_mem->status = UrpcEmpty;
        return LIB_ERR_STRING_TOO_LONG;
    }
    urpc_shared_mem->spawn_req.cmdline_len = cmdline_size;
    strlcpy((char *)&urpc_shared_mem->spawn_req.args[0], cmdline, cmdline_size);
    urpc_shared_mem->status = UrpcMasterData;

    // TODO: Barriers?
    while (urpc_shared_mem->status != UrpcSlaveData);
    assert(urpc_shared_mem->type == SpawnRequest);
    *newpid = urpc_shared_mem->spawn_resp.newpid;
    errval_t err = urpc_shared_mem->spawn_resp.err;
    urpc_shared_mem->status = UrpcEmpty;
    return err;
}
