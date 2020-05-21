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

__attribute__((__used__))
static size_t aos_terminal_read(char *buf, size_t len)
{
    errval_t err;

    struct aos_rpc *serial_rpc = aos_rpc_get_serial_channel();
    size_t i = 0;

    for (i = 0; i < len; i++) {
        err = aos_rpc_serial_getchar(serial_rpc, &buf[i]);
        if (err_is_fail(err)) {
            break;
        }
    }
    return i;
}

__attribute__((__used__))
static size_t aos_terminal_write_char(const char *buf, size_t len)
{
    errval_t err;

    struct aos_rpc *serial_rpc = aos_rpc_get_serial_channel();
    size_t i = 0;

    for (i = 0; i < len; i++) {
        err = aos_rpc_serial_putchar(serial_rpc, buf[i]);
        if (err_is_fail(err)) {
            break;
        }
    }

    return i;
}

__attribute__((__used__))
static size_t aos_terminal_write_str(const char *buf, size_t len)
{
    errval_t err;

    struct aos_rpc *serial_rpc = aos_rpc_get_serial_channel();
    err = aos_rpc_serial_putstr(serial_rpc, (char *) buf, len);
    if (err_is_fail(err)) {
        return 0;
    }
    return len;
}

/* Set libc function pointers */
void barrelfish_libc_glue_init(void)
{
    // XXX: FIXME: Check whether we can use the proper kernel serial, and
    // what we need for that
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

    // TODO Change alignment to `PTABLE_ENTRIES * BASE_PAGE_SIZE` for efficiency?
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
    } else {
        // TODO This is never used, so why set it?
        /*
        struct aos_rpc *init_rpc = aos_rpc_get_init_channel();
        set_init_rpc(init_rpc);
        */

        _libc_terminal_read_func = aos_terminal_read;
        _libc_terminal_write_func = aos_terminal_write_str;

        // This call is to setup the channel to the memory server before
        // ram_alloc() is set to use the RPC call for memory allocation. This
        // is necessary since the channel setup itself already needs to
        // allocate RAM. At this point, the channel setup uses
        // ram_alloc_fixed().
        aos_rpc_get_memory_channel();

        slot_ensure_threshold(32);

        // Reset ram allocator to use remote ram allocator
        err = ram_alloc_set(NULL);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_RAM_ALLOC_SET);
        }
    }

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
