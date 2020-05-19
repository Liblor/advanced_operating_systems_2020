#ifndef _USR_INIT_MONITORSERVER_H_
#define _USR_INIT_MONITORSERVER_H_

#include <aos/aos_rpc.h>
#include <aos/threads.h>
#include <aos/deferred.h>


#define PERIODIC_LOCALTASKS_US 1000
struct monitorserver_cb_state {
};

enum monitorserver_binding_type {
    InitserverUrpc = 0,
    ProcessserverUrpc = 5,
    ProcessLocaltasksUrpc = 10,
    SerialserverUrpc = 15,
    MemoryserverUrpc = 20,
    BlockDriverServerUrpc
};

struct monitorserver_rpc {
    bool is_registered;
    struct aos_rpc ump_rpc;
};

struct monitorserver_state {
    struct thread_mutex mutex;
    struct monitorserver_rpc initserver_rpc;
    struct monitorserver_rpc memoryserver_rpc;
    struct monitorserver_rpc processserver_rpc;
    struct monitorserver_rpc processserver_localtasks_rpc;
    struct monitorserver_rpc serialserver_rpc;
    struct monitorserver_rpc blockdriverserver_rpc;
    struct waitset ws;
    struct periodic_event periodic_localtask;
};

errval_t monitorserver_init(void
);

errval_t monitorserver_register_service(enum monitorserver_binding_type type, struct capref urpc_frame);

// serves lmp requests in own thread
errval_t monitorserver_serve_lmp_in_thread(void);


#endif
