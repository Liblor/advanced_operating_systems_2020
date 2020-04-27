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

errval_t monitorserver_init(void
);

#endif
