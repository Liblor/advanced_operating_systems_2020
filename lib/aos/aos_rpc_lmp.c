#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>

void aos_rpc_lmp_handler_print(char* string, uintptr_t* val, struct capref* cap)
{
    if (string) {
        debug_printf("||TEST %s length %zu \n", string, strlen(string));
    }

    if (val) {
        debug_printf("||TEST %d \n", *val);
    }

    if (cap && !capref_is_null(*cap)) {
        char buf[256];
        debug_print_cap_at_capref(buf, 256, *cap);
        debug_printf("||TEST %s \n", buf);
    }
}

static errval_t lmp_send_message(struct lmp_chan *c, struct rpc_message *msg, lmp_send_flags_t flags)
{
    if (msg->cap == NULL) {
        msg->cap = &NULL_CAP;
    }

    uint32_t size_sent = 0;
    const uint64_t lmp_msg_length_bytes = sizeof(uint64_t ) * LMP_MSG_LENGTH;
    const uint64_t msg_size = sizeof(msg->method) + sizeof(msg->length) + msg->length;
    bool first = true;
    uintptr_t buf[LMP_MSG_LENGTH];

    errval_t err = SYS_ERR_OK;
    while(size_sent < msg_size) {
        uint64_t to_send = MIN(lmp_msg_length_bytes, msg_size - size_sent);
        // TODO copy payload!
        memcpy(buf, msg, to_send);
        memset((char *) buf + to_send, 0, (lmp_msg_length_bytes - to_send));
        err = lmp_chan_send4(c, flags, (first ? *msg->cap : NULL_CAP), buf[0], buf[1], buf[2], buf[3]);
        if (err_is_fail(err)) {
            break;
        }
        size_sent += to_send;
        first = false;
    }
    return err;
}


errval_t aos_rpc_lmp_init(struct aos_rpc *rpc)
{

}

errval_t
aos_rpc_lmp_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    struct rpc_message *msg = malloc(sizeof(struct rpc_message) + sizeof(num));
    if (msg == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->method = Method_Send_Number;
    msg->length = sizeof(num);
    msg->cap = &NULL_CAP;
    memcpy(msg->payload, &num, sizeof(num));

   // TODO: init channel
    errval_t err = lmp_send_message(&rpc->rpc_lmp_chan, msg, LMP_SEND_FLAGS_DEFAULT);
    free(msg);
    return err;
}

errval_t
aos_rpc_lmp_send_string(struct aos_rpc *rpc, const char *string)
{
    struct rpc_message *msg = malloc(sizeof(struct rpc_message) + sizeof(string));
    if (msg == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    msg->method = Method_Send_String;
    msg->length = sizeof(string);
    msg->cap = NULL;
    memcpy(msg->payload, string, sizeof(string));

    // TODO: init channel
    errval_t err = lmp_send_message(&rpc->rpc_lmp_chan, msg, LMP_SEND_FLAGS_DEFAULT);
    free(msg);
    return err;
}

errval_t
aos_rpc_lmp_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                    struct capref *ret_cap, size_t *ret_bytes)
{
    const size_t payload_size = sizeof(bytes) + sizeof(alignment);
    struct rpc_message *msg = malloc(sizeof(struct rpc_message) + payload_size);
    msg->method = Method_Request_Ram_Cap;
    msg->length = payload_size;
    msg->cap = &NULL_CAP;
    memcpy(msg->payload, bytes, sizeof(bytes));
    memcpy(msg->payload + sizeof(bytes), alignment, sizeof(alignment));

    // TODO: implement functionality to request a RAM capability over the
    // given channel and wait until it is delivered.
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    // TODO implement functionality to request a character from
    // the serial driver.
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_serial_putchar(struct aos_rpc *rpc, char c)
{
    // TODO implement functionality to send a character to the
    // serial port.
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_process_spawn(struct aos_rpc *rpc, char *cmdline,
                      coreid_t core, domainid_t *newpid)
{
    // TODO (M5): implement spawn new process rpc
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name)
{
    // TODO (M5): implement name lookup for process given a process id
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                             size_t *pid_count)
{
    // TODO (M5): implement process id discovery
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_get_device_cap(struct aos_rpc *rpc, lpaddr_t paddr, size_t bytes,
                       struct capref *ret_cap)
{
    return LIB_ERR_NOT_IMPLEMENTED;
}

/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_lmp_get_init_channel(void)
{
    //TODO: Return channel to talk to init process
    debug_printf("aos_rpc_lmp_get_init_channel NYI\n");
    return NULL;
}

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_lmp_get_memory_channel(void)
{
    //TODO: Return channel to talk to memory server process (or whoever
    //implements memory server functionality)
    debug_printf("aos_rpc_lmp_get_memory_channel NYI\n");
    return NULL;
}

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_lmp_get_process_channel(void)
{
    //TODO: Return channel to talk to process server process (or whoever
    //implements process server functionality)
    debug_printf("aos_rpc_lmp_get_process_channel NYI\n");
    return NULL;
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_lmp_get_serial_channel(void)
{
    //TODO: Return channel to talk to serial driver/terminal process (whoever
    //implements print/read functionality)
    debug_printf("aos_rpc_lmp_get_serial_channel NYI\n");
    return NULL;
}
