/**
 * \file
 * \brief Barrelfish library initialization.
 */

/*
 * Copyright (c) 2007-2019, ETH Zurich.
 * Copyright (c) 2014, HP Labs.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#include <stdio.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/dispatch.h>
#include <aos/curdispatcher_arch.h>
#include <aos/dispatcher_arch.h>
#include <barrelfish_kpi/dispatcher_shared.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/systime.h>
#include <barrelfish_kpi/domain_params.h>

#include "threads_priv.h"
#include "init.h"

/// Are we the init domain (and thus need to take some special paths)?
static bool init_domain;

static struct aos_rpc rpc;

extern size_t (*_libc_terminal_read_func)(char *, size_t);
extern size_t (*_libc_terminal_write_func)(const char *, size_t);
extern void (*_libc_exit_func)(int);
extern void (*_libc_assert_func)(const char *, const char *, const char *, int);

void libc_exit(int);

__weak_reference(libc_exit, _exit);
void libc_exit(int status)
{
    debug_printf("libc exit NYI!\n");
    thread_exit(status);
    // If we're not dead by now, we wait
    while (1) {}
}

static void libc_assert(const char *expression, const char *file,
                        const char *function, int line)
{
    char buf[512];
    size_t len;

    /* Formatting as per suggestion in C99 spec 7.2.1.1 */
    len = snprintf(buf, sizeof(buf), "Assertion failed on core %d in %.*s: %s,"
                   " function %s, file %s, line %d.\n",
                   disp_get_core_id(), DISP_NAME_LEN,
                   disp_name(), expression, function, file, line);
    sys_print(buf, len < sizeof(buf) ? len : sizeof(buf));
}

__attribute__((__used__))
static size_t syscall_terminal_write(const char *buf, size_t len)
{
    if(len) {
        return sys_print(buf, len);
    }
    return 0;
}

__attribute__((__used__))
static size_t dummy_terminal_read(char *buf, size_t len)
{
    debug_printf("Terminal read NYI!\n");
    return len;
}

/* Set libc function pointers */
void barrelfish_libc_glue_init(void)
{
    // XXX: FIXME: Check whether we can use the proper kernel serial, and
    // what we need for that
    // TODO: change these to use the user-space serial driver if possible
    // TODO: set these functions
    _libc_terminal_read_func = dummy_terminal_read;
    _libc_terminal_write_func = syscall_terminal_write;
    _libc_exit_func = libc_exit;
    _libc_assert_func = libc_assert;
    /* morecore func is setup by morecore_init() */

    // XXX: set a static buffer for stdout
    // this avoids an implicit call to malloc() on the first printf
    static char buf[BUFSIZ];
    setvbuf(stdout, buf, _IOLBF, sizeof(buf));
}

static void recv_cb(void *arg)
{
    debug_printf("recv_cb()\n");
}

/** \brief Initialise libbarrelfish.
 *
 * This runs on a thread in every domain, after the dispatcher is setup but
 * before main() runs.
 */
errval_t barrelfish_init_onthread(struct spawn_domain_params *params)
{
    errval_t err;

    // do we have an environment?
    if (params != NULL && params->envp[0] != NULL) {
        extern char **environ;
        environ = params->envp;
    }

    // Init default waitset for this dispatcher
    struct waitset *default_ws = get_default_waitset();
    waitset_init(default_ws);

    // Initialize ram_alloc state
    ram_alloc_init();
    /* All domains use smallcn to initialize */

    err = ram_alloc_set(ram_alloc_fixed);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RAM_ALLOC_SET);
    }
    err = paging_init();
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_VSPACE_INIT);
    }

    err = slot_alloc_init();
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC_INIT);
    }

    err = morecore_init(BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_MORECORE_INIT);
    }

    // Initialize LMP endpoint subsystem.
    lmp_endpoint_init();

    if (init_domain) {
        // Endpoint to the dispatcher itself.
        err = cap_retype(cap_selfep, cap_dispatcher, 0, ObjType_EndPointLMP, 0, 1);
        if (err_is_fail(err)) {
            debug_printf("cap_retype() failed: %s\n", err_getstring(err));
            return err_push(err, LIB_ERR_CAP_RETYPE);
        }
    }

    struct lmp_chan *lc = (struct lmp_chan*) malloc(sizeof(struct lmp_chan));

    if (init_domain) {
        lmp_chan_accept(lc, DEFAULT_LMP_BUF_WORDS, NULL_CAP);
        lmp_chan_alloc_recv_slot(lc);
        cap_copy(cap_chan_init, lc->local_cap);

        err = lmp_chan_register_recv(lc, get_default_waitset(), MKCLOSURE(recv_cb, &lc));
        DEBUG_ERR(err, "lmp_chan_register_recv()");
    } else {
        lmp_chan_init(lc);

        struct capref cap_ep;
        err = endpoint_create(DEFAULT_LMP_BUF_WORDS, &cap_ep, &lc->endpoint);
        DEBUG_ERR(err, "endpoint_create()");

        lc->local_cap = cap_ep;
        lc->remote_cap = cap_chan_init;

        err = lmp_chan_register_recv(lc, get_default_waitset(), MKCLOSURE(recv_cb, &lc));
        DEBUG_ERR(err, "lmp_chan_register_recv()");

        err = lmp_chan_send0(lc, LMP_SEND_FLAGS_DEFAULT, cap_ep);
        DEBUG_ERR(err, "lmp_chan_send0()");
        if (lmp_err_is_transient(err)) {
            debug_printf("error is transient\n");
        } else {
            debug_printf("error is NOT transient\n");
        }

        err = event_dispatch(get_default_waitset());
        DEBUG_ERR(err, "event_dispatch()");

        aos_rpc_init(&rpc);
        set_init_rpc(&rpc);
    }

    // TODO MILESTONE 3:
    /* register ourselves with init:
     * [X] allocate lmp channel structure
     * [X] create local endpoint
     * [X] set remote endpoint to init's endpoint
     * [X] set receive handler
     * [X] send local ep to init
     * [X] wait for init to acknowledge receiving the endpoint
     * [X] initialize init RPC client with lmp channel
     * [X] set init RPC client in our program state
     */

    /* TODO MILESTONE 3: now we should have a channel with init set up and can
     * use it for the ram allocator */

    // right now we don't have the nameservice & don't need the terminal
    // and domain spanning, so we return here
    return SYS_ERR_OK;
}


/**
 *  \brief Initialise libbarrelfish, while disabled.
 *
 * This runs on the dispatcher's stack, while disabled, before the dispatcher is
 * setup. We can't call anything that needs to be enabled (ie. cap invocations)
 * or uses threads. This is called from crt0.
 */
void barrelfish_init_disabled(dispatcher_handle_t handle, bool init_dom_arg);
void barrelfish_init_disabled(dispatcher_handle_t handle, bool init_dom_arg)
{
    init_domain = init_dom_arg;
    disp_init_disabled(handle);
    thread_init_disabled(handle, init_dom_arg);
}
