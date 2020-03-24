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

errval_t aos_rpc_lmp_init(struct aos_rpc *rpc)
{
    reset_recv_state(&rpc->shared.lmp.state);

    return SYS_ERR_OK;
}

static void recv_cb(void *arg)
{
    struct aos_rpc *rpc = (struct aos_rpc *) arg;
    struct aos_rpc_lmp_recv_state *recv_state = &rpc->shared.lmp.state;
    struct lmp_chan *lc = rpc->shared.lmp.lc;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;

    err = lmp_chan_recv(lc, &msg, &cap);
    if (err_is_fail(err) && lmp_err_is_transient(err)) {
        // reregister
        lmp_chan_register_recv(lc, get_default_waitset(), MKCLOSURE(recv_cb, arg));
        return;
    }

    // TODO: Realloc payload to fit more data.

    recv_state->count += msg.buf.msglen;
    memcpy(recv_state->msg.payload, msg.buf.words, msg.buf.msglen);

    debug_printf("msg buflen %zu\n", msg.buf.msglen);
    debug_printf("msg->words[0] = 0x%lx\n", msg.words[0]);

    if (recv_state->count >= recv_state->msg->length) {
        // All segments received
        // TODO: Call our callback
    } else {
        lmp_chan_register_recv(lc, get_default_waitset(), MKCLOSURE(recv_cb, arg));
    }
}

static inline errval_t wait_for_ack(struct aos_rpc *rpc, struct aos_rpc_lmp_recv_state *s)
{
    errval_t err;

    while (s->count < s->msg->length) {
        err = event_dispatch(rpc->ws);
        // TODO: Handle error.
    }
}

static inline void reset_recv_state(struct aos_rpc_lmp_recv_state *s)
{
    s->msg.method = RPC_MESSAGE_TYPE_UNKNOWN;
    s->msg.length = 0;
    s->msg.payload = NULL;
    s->count = 0;
}

static inline errval_t wait_for_response(struct aos_rpc *rpc)
{
    errval_t err;

    reset_recv_state(&rpc->shared.lmp.state);

    err = lmp_chan_register_recv(rpc->shared.lc, rpc->shared.ws, MKCLOSURE(recv_cb, rpc));
    // TODO: Handle error.

    err = wait_for_ack(&rpc->shared.lmp.state);
    // TODO: Handle error.
}

errval_t aos_rpc_lmp_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    // TODO: implement functionality to send a number over the channel
    // given channel and wait until the ack gets returned.
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
    //lmp_chan_init(struct lmp_chan *lc);
    //errval_t lmp_chan_alloc_recv_slot(struct lmp_chan *lc)
    //errval_t lmp_chan_accept(struct lmp_chan *lc,
                         //size_t buflen_words, struct capref endpoint)
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
