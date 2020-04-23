#include <aos/aos.h>
#include <aos/urpc.h>
#include <aos/kernel_cap_invocations.h>


static volatile struct urpc_shared_mem *urpc_shared_mem;

urpc_slave_spawn_process_cb urpc_slave_spawn_process = NULL;

errval_t master_urpc_init(void)
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
    URPC_BARRIER;
    urpc_shared_mem->status = UrpcEmpty;
    URPC_BARRIER;

    return SYS_ERR_OK;
}

errval_t urpc_send_boot_info(struct bootinfo *bootinfo)
{
    URPC_BARRIER;
    while (urpc_shared_mem->status != UrpcEmpty) {
        URPC_BARRIER;
        thread_yield();
        URPC_BARRIER;
    }
    URPC_BARRIER;
    urpc_shared_mem->status = UrpcWritting;
    URPC_BARRIER;
    urpc_shared_mem->type = BootInfo;
    memcpy((void *) &urpc_shared_mem->bootinfo_msg.bi, bootinfo,
            sizeof(struct bootinfo) + bootinfo->regions_length * sizeof(struct mem_region));
    struct frame_identity mmstring_identity;
    errval_t err = frame_identify(cap_mmstrings, &mmstring_identity);
    if (err_is_fail(err)) {
        URPC_BARRIER;
        urpc_shared_mem->status = UrpcEmpty;
        URPC_BARRIER;
        return err;
    }
    urpc_shared_mem->bootinfo_msg.mmstring_base = mmstring_identity.base;
    urpc_shared_mem->bootinfo_msg.mmstring_size = mmstring_identity.bytes;
    URPC_BARRIER;
    urpc_shared_mem->status = UrpcMasterData;
    URPC_BARRIER;
    return SYS_ERR_OK;
}

errval_t urpc_send_spawn_request(
        char *cmdline,
        coreid_t core,
        domainid_t *newpid
) {
    // TODO: Barriers?
    URPC_BARRIER;
    while (urpc_shared_mem->status != UrpcEmpty) {
        URPC_BARRIER;
        thread_yield();
        URPC_BARRIER;
    }
    URPC_BARRIER;
    urpc_shared_mem->status = UrpcWritting;
    URPC_BARRIER;
    urpc_shared_mem->type = SpawnRequest;
    size_t cmdline_size = strlen(cmdline) + 1;
    if (cmdline_size > URPC_SHARED_MEM_SIZE - sizeof(struct urpc_shared_mem)) {
        URPC_BARRIER;
        urpc_shared_mem->status = UrpcEmpty;
        URPC_BARRIER;
        return LIB_ERR_STRING_TOO_LONG;
    }
    urpc_shared_mem->spawn_req.cmdline_size = cmdline_size;
    strlcpy((char *)&urpc_shared_mem->spawn_req.args[0], cmdline, cmdline_size);
    URPC_BARRIER;
    urpc_shared_mem->status = UrpcMasterData;
    URPC_BARRIER;

    // TODO: Barriers?
    URPC_BARRIER;
    while (urpc_shared_mem->status != UrpcSlaveData) {
        URPC_BARRIER;
        thread_yield();
        URPC_BARRIER;
    }
    assert(urpc_shared_mem->type == SpawnResponse);
    *newpid = urpc_shared_mem->spawn_resp.newpid;
    errval_t err = urpc_shared_mem->spawn_resp.err;
    URPC_BARRIER;
    urpc_shared_mem->status = UrpcEmpty;
    URPC_BARRIER;
    return err;
}


errval_t urpc_slave_init(void)
{
    errval_t err;
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

    return SYS_ERR_OK;
}

errval_t urpc_receive_bootinfo(
        struct bootinfo **bootinfo,
        genpaddr_t *ret_mmstrings_base,
        gensize_t *ret_mmstrings_size
)
{
    errval_t err;
    debug_printf("waiting for UrpcMasterData\n");
    URPC_BARRIER;
    while (urpc_shared_mem->status != UrpcMasterData) {
        URPC_BARRIER;
        thread_yield();
        URPC_BARRIER;
    }

    *ret_mmstrings_base = urpc_shared_mem->bootinfo_msg.mmstring_base;
    *ret_mmstrings_size = urpc_shared_mem->bootinfo_msg.mmstring_size;
    size_t bi_region_len = urpc_shared_mem->bootinfo_msg.bi.regions_length;
    *bootinfo = malloc(sizeof(struct bootinfo) + bi_region_len * sizeof(struct mem_region));
    if (*bootinfo == NULL) {
        err = LIB_ERR_MALLOC_FAIL;
        goto clean_up;
    }
    memcpy(*bootinfo,
           (void *) &urpc_shared_mem->bootinfo_msg.bi,
           sizeof(struct bootinfo) + bi_region_len * sizeof(struct mem_region)
    );

    err = SYS_ERR_OK;
clean_up:
    URPC_BARRIER;
    urpc_shared_mem->status = UrpcEmpty;
    URPC_BARRIER;
    return err;
}

/* return LIB_ERR_NO_EVENT on no msg */
errval_t urpc_slave_serve_non_block(void)
{
    assert(urpc_slave_spawn_process != NULL);
    errval_t err;
    URPC_BARRIER;
    if (urpc_shared_mem->status != UrpcMasterData) {
        return LIB_ERR_NO_EVENT;
    }
    URPC_BARRIER;
    debug_printf("got UrpcMasterData\n");

    switch (urpc_shared_mem->type) {
        case BootInfo:
            assert(false);
            break;
        case SpawnRequest: {
            struct urpc_spawn_request *req = (struct urpc_spawn_request *) &urpc_shared_mem->spawn_req;
            domainid_t pid;
            err = urpc_slave_spawn_process(req->args, &pid);
            struct urpc_spawn_response *resp = (struct urpc_spawn_response *) &urpc_shared_mem->spawn_resp;
            resp->newpid = pid;
            resp->err = err;
            urpc_shared_mem->type = SpawnResponse;
            URPC_BARRIER;
            urpc_shared_mem->status = UrpcSlaveData;
            URPC_BARRIER;
            break;
        }
        case SpawnResponse:
            // we never receive a spawn response as slave
            assert(false);
            break;
        default:
            debug_printf("unknown urpc type: %p\n", urpc_shared_mem->type);
            break;
    }
    return SYS_ERR_OK;
}
