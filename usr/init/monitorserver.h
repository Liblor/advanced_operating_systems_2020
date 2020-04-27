#ifndef _USR_INIT_MONITORSERVER_H_
#define _USR_INIT_MONITORSERVER_H_

#include <aos/aos_rpc.h>

struct monitorserver_cb_state {
};

struct monitorserver_state {
    struct aos_rpc initserver;
    struct aos_rpc memoryserver;
    struct aos_rpc processserver;
    struct aos_rpc serialserver;
};

struct monitorserver_urpc_caps {
    struct capref spawn_server;
    struct capref init_server;
    struct capref serial_server;
    struct capref localtask_spawn;
};


errval_t monitorserver_init(struct monitorserver_urpc_caps *urpc_caps
);

#endif
