/**
 * \file User-level interrupt handler support
 * \brief
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2011, 2020 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#include <aos/aos.h>
#include <aos/lmp_endpoints.h>
#include <aos/inthandler.h>

errval_t inthandler_alloc_dest_irq_cap(int vec_hint, struct capref *retcap)
{
    errval_t err;

    err = slot_alloc(retcap);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "slot_alloc");
        return err;
    }

    err = invoke_irqtable_alloc_dest_cap(cap_irq, *retcap, vec_hint);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "could not allocate dest cap!");
        return err;
    }  

    return SYS_ERR_OK;
}


struct interrupt_handler_state {
    struct lmp_endpoint *idcep;
    struct waitset *ws;
    struct event_closure uc;
};

static void generic_interrupt_handler(void *arg)
{
    struct interrupt_handler_state *state = arg;
    errval_t err;

    // consume message
    struct lmp_recv_msg buf = LMP_RECV_MSG_INIT;
    err = lmp_endpoint_recv(state->idcep, &buf.buf, NULL);
    assert(err_is_ok(err));

    if (buf.buf.msglen == 1 && buf.words[0] == 1) {
        // domain moved notification. Don't do this on AOS
        USER_PANIC("Domain got moved, need to reregister for interrupt\n");
    } else {
        state->uc.handler(state->uc.arg);
    }
    // re-register
    err = lmp_endpoint_register(state->idcep, state->ws,
            MKCLOSURE(generic_interrupt_handler, arg));
    assert(err_is_ok(err));
}


errval_t inthandler_setup(struct capref dst_cap, struct waitset *ws,
                          struct event_closure handler)
{
    errval_t err;

    // alloc state
    struct interrupt_handler_state *state;
    state = malloc(sizeof(struct interrupt_handler_state));
    assert(state != NULL);

    state->uc = handler;
    state->ws = ws;

    // create endpoint to handle interrupts 
    struct capref epcap;

    // use minimum-sized endpoint, because we don't need to buffer >1 interrupt
    err = endpoint_create(LMP_RECV_LENGTH, &epcap, &state->idcep);
    if (err_is_fail(err)) {
        free(state);
        return err_push(err, LIB_ERR_ENDPOINT_CREATE);
    }

    // connect irq_dest with EP 
    err = invoke_irqdest_connect(dst_cap, epcap);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Could not connect irq_cap and endpoint");
        return err;
    }

    // register to receive on this endpoint
    err = lmp_endpoint_register(state->idcep, ws,
            MKCLOSURE(generic_interrupt_handler, state));
    if (err_is_fail(err)) {
        lmp_endpoint_free(state->idcep);
        // TODO: release vector
        free(state);
        return err_push(err, LIB_ERR_LMP_ENDPOINT_REGISTER);
    }

    return SYS_ERR_OK;
}
