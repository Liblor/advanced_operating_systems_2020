#ifndef _USR_INIT_MONITORSERVER_H_
#define _USR_INIT_MONITORSERVER_H_

#include <aos/aos_rpc.h>

struct monitorserver_cb_state {
};

struct monitorserver_state {
    struct aos_rpc server_rpc;
};

errval_t monitorserver_init(void
);

#endif
