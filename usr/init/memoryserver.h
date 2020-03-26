#ifndef _USR_INIT_MEMORYSERVER_H_
#define _USR_INIT_MEMORYSERVER_H_

#include <aos/aos_rpc.h>

typedef errval_t (* ram_cap_callback_t)(const size_t bytes, const size_t align, struct capref *retcap, size_t *retbytes);

struct memoryserver_cb_state {
};

errval_t memoryserver_init(
    ram_cap_callback_t ram_cap_cb
);

#endif
