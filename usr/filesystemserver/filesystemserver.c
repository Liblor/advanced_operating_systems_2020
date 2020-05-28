#include <aos/aos.h>
#include <aos/cache.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>
#include <rpc/server/ump.h>
#include <drivers/sdhc.h>
#include <maps/imx8x_map.h>
#include <aos/nameserver.h>
#include <fs/fat32.h>

struct fileserver_state {
    struct fat32_mnt *mnt;
};

//static struct sdhc_s *sdhc_s;

static inline errval_t fail_msg(
    enum rpc_message_method method,
    struct rpc_message **ret_msg
) {
    *ret_msg = malloc(sizeof(struct rpc_message));
    if (*ret_msg == NULL) { return LIB_ERR_MALLOC_FAIL; }
    (*ret_msg)->cap = NULL_CAP;
    (*ret_msg)->msg.method = method;
    (*ret_msg)->msg.payload_length = 0;
    (*ret_msg)->msg.status = Status_Error;
    return SYS_ERR_OK;
}

static inline errval_t errval_msg(
    enum rpc_message_method method,
    errval_t errno,
    struct rpc_message **ret_msg
) {
    *ret_msg = malloc(sizeof(struct rpc_message) + sizeof(errval_t));
    if (*ret_msg == NULL) { return LIB_ERR_MALLOC_FAIL; }
    (*ret_msg)->cap = NULL_CAP;
    (*ret_msg)->msg.method = method;
    (*ret_msg)->msg.payload_length = sizeof(errval_t);
    (*ret_msg)->msg.status = Status_Ok;
    memcpy((*ret_msg)->msg.payload, &errno, sizeof(errval_t));
    return SYS_ERR_OK;
}

static inline errval_t size_t_msg(
    enum rpc_message_method method,
    errval_t errno,
    size_t num,
    struct rpc_message **ret_msg
) {
    *ret_msg = malloc(sizeof(struct rpc_message) + sizeof(errval_t) + sizeof(num));
    if (*ret_msg == NULL) { return LIB_ERR_MALLOC_FAIL; }
    (*ret_msg)->cap = NULL_CAP;
    (*ret_msg)->msg.method = method;
    (*ret_msg)->msg.payload_length = sizeof(errval_t) + sizeof(size_t);
    (*ret_msg)->msg.status = Status_Ok;
    memcpy((*ret_msg)->msg.payload, &errno, sizeof(errno));
    memcpy(((char *)(*ret_msg)->msg.payload + sizeof(errno)), &num, sizeof(num));
    return SYS_ERR_OK;
}

static inline errval_t fsinfo_msg(
    enum rpc_message_method method,
    errval_t errno,
    struct fs_fileinfo *fsinfo,
    struct rpc_message **ret_msg
) {
    *ret_msg = malloc(sizeof(struct rpc_message) + sizeof(errval_t) + sizeof(struct fs_fileinfo));
    if (*ret_msg == NULL) { return LIB_ERR_MALLOC_FAIL; }
    (*ret_msg)->cap = NULL_CAP;
    (*ret_msg)->msg.method = method;
    (*ret_msg)->msg.payload_length = sizeof(errval_t) + sizeof(struct fs_fileinfo);
    (*ret_msg)->msg.status = Status_Ok;
    memcpy((*ret_msg)->msg.payload, &errno, sizeof(errno));
    memcpy(((char *)(*ret_msg)->msg.payload + sizeof(errno)), fsinfo, sizeof(struct fs_fileinfo));
    return SYS_ERR_OK;
}

static inline errval_t success_msg_pointer(
    enum rpc_message_method method,
    errval_t errno,
    lvaddr_t pointer,
    struct rpc_message **ret_msg
) {
    *ret_msg = calloc(sizeof(struct rpc_message) + sizeof(errno) + sizeof(pointer), 1);
    if (*ret_msg == NULL) { return LIB_ERR_MALLOC_FAIL; }
    (*ret_msg)->cap = NULL_CAP;
    (*ret_msg)->msg.method = method;
    (*ret_msg)->msg.payload_length = sizeof(errno) + sizeof(pointer);
    (*ret_msg)->msg.status = Status_Ok;
    memcpy((*ret_msg)->msg.payload, &errno, sizeof(errno));
    memcpy(((char *)(*ret_msg)->msg.payload + sizeof(errno)), &pointer, sizeof(pointer));
    return SYS_ERR_OK;
}

static inline errval_t buf_msg(
    enum rpc_message_method method,
    errval_t errno,
    const char *buf,
    size_t buf_size,
    struct rpc_message **ret_msg
) {
    *ret_msg = calloc(sizeof(struct rpc_message) + sizeof(errno) + buf_size, 1);
    if (*ret_msg == NULL) { return LIB_ERR_MALLOC_FAIL; }
    (*ret_msg)->cap = NULL_CAP;
    (*ret_msg)->msg.method = method;
    (*ret_msg)->msg.payload_length = sizeof(errno) + buf_size;
    (*ret_msg)->msg.status = Status_Ok;
    memcpy((*ret_msg)->msg.payload, &errno, sizeof(errno));
    memcpy(((char *)(*ret_msg)->msg.payload + sizeof(errno)), buf, buf_size);
    return SYS_ERR_OK;
}

#if 0
static inline errval_t read_block(
    uint32_t index,
    struct fileserver_state *server_state
) {
    errval_t err;
    arm64_dcache_wbinv_range(server_state->read_vaddr, SDHC_BLOCK_SIZE);
    err = sdhc_read_block(sdhc_s, index, server_state->read_paddr);
    if (err_is_fail(err)) { return err; }
    return SYS_ERR_OK;
}

static inline errval_t write_block(
    uint32_t index,
    struct fileserver_state *server_state
) {
    errval_t err;
    arm64_dcache_wb_range(server_state->write_vaddr, SDHC_BLOCK_SIZE);
    err = sdhc_write_block(sdhc_s, index, server_state->write_paddr);
    if (err_is_fail(err)) { return err; }
    return SYS_ERR_OK;
}
#endif

static errval_t handle_path_to_handler(
    struct fileserver_state *server_state,
    struct rpc_message *msg,
    errval_t (*fs_str_to_handler)(void *, const char *, fat32_handle_t*),
    struct rpc_message **ret_msg
) {
    errval_t err;
    size_t name_len = msg->msg.payload_length;
    char *name = calloc(name_len, 1);
    if (name == NULL) {
        fail_msg(msg->msg.method, ret_msg);
        return LIB_ERR_MALLOC_FAIL;
    }
    memcpy(name, msg->msg.payload, name_len);
    name[name_len - 1] = '\0';

    fat32_handle_t handle;
    err = fs_str_to_handler(server_state->mnt, name, &handle);
    free(name);
    lvaddr_t ptr = (lvaddr_t)handle;
    return success_msg_pointer(msg->msg.method, err, ptr, ret_msg);
}

static errval_t handle_path_to_ok(
    struct fileserver_state *server_state,
    struct rpc_message *msg,
    errval_t (*fs_path)(void *, const char *),
    struct rpc_message **ret_msg
) {
    errval_t err;
    size_t name_len = msg->msg.payload_length;
    char *name = calloc(name_len, 1);
    if (name == NULL) {
        fail_msg(msg->msg.method, ret_msg);
        return LIB_ERR_MALLOC_FAIL;
    }
    memcpy(name, msg->msg.payload, name_len);
    name[name_len - 1] = '\0';

    err = fs_path(server_state->mnt, name);
    free(name);
    return errval_msg(msg->msg.method, err, ret_msg);
}

static errval_t handle_close(
    struct fileserver_state *server_state,
    struct rpc_message *msg,
    errval_t (*close)(void *, fat32_handle_t),
    struct rpc_message **ret_msg
) {
    errval_t err;
    lvaddr_t h;
    memcpy(&h, msg->msg.payload, sizeof(lvaddr_t));

    fat32_handle_t handle = (fat32_handle_t)h;
    err = close(server_state->mnt, handle);
    return errval_msg(msg->msg.method, err, ret_msg);
}

static errval_t handle_dir_read_next(
    struct fileserver_state *server_state,
    struct rpc_message *msg,
    struct rpc_message **ret_msg
) {
    errval_t err;
    lvaddr_t h;
    memcpy(&h, msg->msg.payload, sizeof(lvaddr_t));

    fat32_handle_t handle = (fat32_handle_t)h;
    char *name;
    err = fat32_dir_read_next(server_state->mnt, handle, &name, NULL);
    size_t name_size = strlen(name) + 1;
    errval_t ret_err = buf_msg(msg->msg.method, err, name, name_size, ret_msg);
    if (err_is_ok(err)) {
        free(name);
    }
    return ret_err;
}

static errval_t handle_tell(
    struct fileserver_state *server_state,
    struct rpc_message *msg,
    struct rpc_message **ret_msg
) {
    errval_t err;
    lvaddr_t h;
    memcpy(&h, msg->msg.payload, sizeof(lvaddr_t));

    fat32_handle_t handle = (fat32_handle_t)h;
    size_t pos;
    err = fat32_tell(server_state->mnt, handle, &pos);
    return size_t_msg(msg->msg.method, err, pos, ret_msg);
}

static errval_t handle_stat(
    struct fileserver_state *server_state,
    struct rpc_message *msg,
    struct rpc_message **ret_msg
) {
    errval_t err;
    lvaddr_t h;
    memcpy(&h, msg->msg.payload, sizeof(lvaddr_t));

    fat32_handle_t handle = (fat32_handle_t)h;
    struct fs_fileinfo fs_info;
    err = fat32_stat(server_state->mnt, handle, &fs_info);
    return fsinfo_msg(msg->msg.method, err, &fs_info, ret_msg);
}

static errval_t handle_read(
    struct fileserver_state *server_state,
    struct rpc_message *msg,
    struct rpc_message **ret_msg
) {
    errval_t err;
    lvaddr_t h;
    size_t bytes;
    memcpy(&h, msg->msg.payload, sizeof(lvaddr_t));
    memcpy(&bytes, (char*)msg->msg.payload + sizeof(lvaddr_t), sizeof(bytes));
    char *buf = calloc(bytes, 1);
    if (buf == NULL) { debug_printf("MALLOCFAIL\n"); return LIB_ERR_MALLOC_FAIL; }
    fat32_handle_t handle = (fat32_handle_t)h;
    err = fat32_read(server_state->mnt, handle, buf, bytes, &bytes);
    err = buf_msg(msg->msg.method, err, buf, bytes, ret_msg);
    free(buf);
    return err;
}

static errval_t handle_seek(
    struct fileserver_state *server_state,
    struct rpc_message *msg,
    struct rpc_message **ret_msg
) {
    errval_t err;
    lvaddr_t h;
    off_t offset;
    enum fs_seekpos whence;
    memcpy(&h, msg->msg.payload, sizeof(lvaddr_t));
    memcpy(&offset, (char*)msg->msg.payload + sizeof(lvaddr_t), sizeof(offset));
    memcpy(&whence, (char*)msg->msg.payload + sizeof(lvaddr_t) + sizeof(offset), sizeof(whence));
    fat32_handle_t handle = (fat32_handle_t)h;
    err = fat32_seek(server_state->mnt, handle, whence, offset);
    return errval_msg(msg->msg.method, err, ret_msg);
}

static errval_t handle_write(
    struct fileserver_state *server_state,
    struct rpc_message *msg,
    struct rpc_message **ret_msg
) {
    errval_t err;
    lvaddr_t h;
    memcpy(&h, msg->msg.payload, sizeof(lvaddr_t));
    fat32_handle_t handle = (fat32_handle_t)h;
    size_t buf_size = msg->msg.payload_length - sizeof(lvaddr_t);
    assert(buf_size < msg->msg.payload_length);

    size_t written;
    err = fat32_write(
        server_state->mnt,
        handle,
        sizeof(lvaddr_t) + (char*)msg->msg.payload,
        buf_size,
        &written
    );
    return size_t_msg(msg->msg.method, err, written, ret_msg);
}

static void ns_service_handler(
    void *st,
    void *message,
    size_t bytes,
    void **response,
    size_t *response_bytes,
    struct capref tx_cap,
    struct capref *rx_cap)
{
    errval_t err;
    struct rpc_message *msg = message;
    struct rpc_message *resp_msg = NULL;
    switch (msg->msg.method) {
        case Method_File_System_Open:
            err = handle_path_to_handler(st, msg, fat32_open, &resp_msg);
            break;
        case Method_File_System_Open_Dir:
            err = handle_path_to_handler(st, msg, fat32_opendir, &resp_msg);
            break;
        case Method_File_System_Create:
            err = handle_path_to_handler(st, msg, fat32_create, &resp_msg);
            break;
        case Method_File_System_Mkdir:
            err = handle_path_to_ok(st, msg, fat32_mkdir, &resp_msg);
            break;
        case Method_File_System_Rm:
            err = handle_path_to_ok(st, msg, fat32_remove, &resp_msg);
            break;
        case Method_File_System_Rmdir:
            err = handle_path_to_ok(st, msg, fat32_rmdir, &resp_msg);
            break;
        case Method_File_System_Dir_Read_Next:
            err = handle_dir_read_next(st, msg, &resp_msg);
            break;
        case Method_File_System_Close:
            err = handle_close(st, msg, fat32_close, &resp_msg);
            break;
        case Method_File_System_Closedir:
            err = handle_close(st, msg, fat32_closedir, &resp_msg);
            break;
        case Method_File_System_Tell:
            err = handle_tell(st, msg, &resp_msg);
            break;
        case Method_File_System_Stat:
            err = handle_stat(st, msg, &resp_msg);
            break;
        case Method_File_System_Read:
            err = handle_read(st, msg, &resp_msg);
            break;
        case Method_File_System_Seek:
            err = handle_seek(st, msg, &resp_msg);
            break;
        case Method_File_System_Write:
            err = handle_write(st, msg, &resp_msg);
            break;
        default:
            debug_printf("unknown method given: %d\n", msg->msg.method);
            err = AOS_ERR_LMP_MSGTYPE_UNKNOWN;      // TODO: fix error code
            break;
    }
    if (err_is_fail(err)) {
        debug_printf("ns_service_handler(..) in filesystemserver.c failed: %s\n", err_getstring(err));
    }
    if (resp_msg == NULL) {
        *response = NULL;
        *response_bytes = 0;
    } else {
        *response = resp_msg;
        *response_bytes = sizeof(struct rpc_message) + resp_msg->msg.payload_length;
    }
}

static inline errval_t init_fileserver_state(struct fileserver_state *st)
{
    //errval_t err;
    return mount_fat32("/sdcard", &st->mnt);
}

int main(int argc, char *argv[])
{
    errval_t err;
    err = nameservice_wait_for_timeout(NAMESERVICE_BLOCKDRIVER, 60, 100000);
    if (err_is_fail(err)) { return 0; }
    printf("Fileserver spawned.\n");
    struct fileserver_state *st = malloc(sizeof(struct fileserver_state));
    if (st == NULL) {
        return 1;
    }
    err = init_fileserver_state(st);
    if (err_is_fail(err)) {
        return 1;
    }
    err = nameservice_register(NAMESERVICE_FILESYSTEM, ns_service_handler, st);
    if (err_is_fail(err)) {
        debug_printf("nameservice_register() failed: %s\n", err_getstring(err));
        abort();
    }
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        err = event_dispatch(default_ws);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in event_dispatch");
            abort();
        }
        thread_yield();
    }
    return SYS_ERR_OK;
}
