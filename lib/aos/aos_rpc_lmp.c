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



static send_message(struct lmp_chan *c, uintptr_t *msgbuf,
                    size_t msg_words, size_t *words_sent) {
    uintptr_t buf[LMP_MSG_LENGTH];
    if (msg_words > LMP_MSG_LENGTH) {
        msg_words = LMP_MSG_LENGTH;
    }
    memcpy(buf, msgbuf, msg_words * sizeof(uintptr_t));
    memset(buf + msg_words, 0, (LMP_MSG_LENGTH - msg_words));
    if (words_sent) {
        *words_sent = msg_words;
    }
    return lmp_chan_send4(c, LMP_SEND_FLAGS_DEFAULT, NULL_CAP, buf[0], buf[1], buf[2], buf[3]);

}

//struct rpc_lmp_segment {
//    uintptr_t chunk[4]; ///< Bytes that can be sent at a time.
//};


//struct rpc_message {
//    uint8_t method;   ///< Method identifier, i.e., "send an int".
//    uint32_t length; ///< The length of the message.
//    uintptr_t *payload; ///< The total payload data of the message.
//};


static errval_t lmp_send_message(struct lmp_chan *c, struct rpc_message *msg, lmp_send_flags_t flags)
{
    uint32_t size_sent = 0;
    const uint64_t lmp_msg_length_bytes = sizeof(uint64_t ) * LMP_MSG_LENGTH;
    const uint64_t msg_size = sizeof(msg->method) + sizeof(msg->length) + msg->length;
    bool first = true;
    uintptr_t buf[LMP_MSG_LENGTH];

    errval_t err = SYS_ERR_OK;

    while(size_sent < msg_size) {
        uint64_t to_send = MIN(lmp_msg_length_bytes, msg_size - size_sent);
        memcpy(buf, msg, to_send);
        memset(buf + to_send, 0, (lmp_msg_length_bytes - to_send));
        err = lmp_chan_send4(c, flags, (first ? *msg->cap : NULL_CAP), buf[0], buf[1], buf[2], buf[3]);
        if (err_is_fail(err)) {
            break;
        }
        size_sent += to_send;
        first = false;
    }
    return err;
}

errval_t
aos_rpc_lmp_send_number(struct aos_rpc *rpc, uintptr_t num)
{

    struct rpc_message msg = {
        .method = Method_Send_Number,
        .length = sizeof(num),
        .cap = &NULL_CAP,
        .payload = &num
    };

//    return lmp_send_message(&msg, );
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_send_string(struct aos_rpc *rpc, const char *string)
{
    // TODO: implement functionality to send a string over the given channel
    // and wait for a response.
    return SYS_ERR_OK;
}

errval_t
aos_rpc_lmp_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                    struct capref *ret_cap, size_t *ret_bytes)
{
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