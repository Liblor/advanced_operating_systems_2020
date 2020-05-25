#ifndef _USR_INIT_MONITORSERVER_H_
#define _USR_INIT_MONITORSERVER_H_

#include <aos/aos_rpc.h>
#include <aos/threads.h>
#include <aos/deferred.h>
#include <rpc/server/lmp.h>


#define MONITORSERVER_PERIODIC_FORWARD_RESPONSE_EVENT_US 100

struct monitorserver_cb_state {
};

enum monitorserver_binding_type {
    SerialserverUrpc = 15,
    MemoryserverUrpc = 20,
    NameserverUrpc = 25,
    BlockDriverServerUrpc = 30,
};

struct monitorserver_rpc {
    bool is_registered;
    struct aos_rpc ump_rpc;
};

struct monitorserver_state {
    struct thread_mutex mutex;

    struct rpc_lmp_server lmp_server;

    struct monitorserver_rpc memoryserver_rpc;
    struct monitorserver_rpc serialserver_rpc;
    struct monitorserver_rpc nameserver_rpc;
    struct monitorserver_rpc blockdriverserver_rpc;
    struct waitset ws;
    struct periodic_event periodic_localtask;

    struct periodic_event forward_response_periodic_ev;
    struct aos_rpc *rpc_forward_request_pending;
    struct aos_rpc *rpc_forward_response_pending;
    uint8_t method_forward_request_pending;
    struct nameserver_state *ns_state;
};

errval_t monitorserver_init(struct nameserver_state *ns_state);

errval_t monitorserver_register_service(enum monitorserver_binding_type type, struct capref urpc_frame);

// serves lmp requests in own thread
errval_t monitorserver_serve_lmp_in_thread(void);


#endif
