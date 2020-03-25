#ifndef _USR_INIT_INITSERVER_H_
#define _USR_INIT_INITSERVER_H_

#include <aos/rpc.h>

struct {
    struct aos_rpc rpc;
    uint32_t count; ///< How much was read from the client already.
} callback_state;

errval_t initserver_init(void);

#endif
