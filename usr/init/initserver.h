#ifndef _USR_INIT_INITSERVER_H_
#define _USR_INIT_INITSERVER_H_

#include <aos/aos_rpc.h>

// Client-specific state.
struct callback_state {
    struct aos_rpc rpc;
    uint32_t count; ///< How much was read from the client already.
};

errval_t initserver_init(void);

#endif
