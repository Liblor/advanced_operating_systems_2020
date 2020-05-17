#ifndef _USR_INIT_SERIALSERVER_H_
#define _USR_INIT_SERIALSERVER_H_

#include <aos/aos_rpc.h>
#include "circular_buf.h"

#define SERIAL_SERVER_DEBUG_ON

#if defined(SERIAL_SERVER_DEBUG_ON)
#define SERIAL_SERVER_DEBUG(x...) debug_printf("serial-server:" x)
#else
#define SERIAL_SERVER_DEBUG(x...) ((void)0)
#endif

// enable to use kernel functions instead of userspace
// #define SERIAL_SERVER_USE_KERNEL

#define SERIAL_BUF_SLOTS 256

struct serial_buf_entry {
    char val;
} __packed;

struct serialserver_state {
    serial_session_t curr_read_session;
    struct aos_rpc *deferred_rpc;
    struct cbuf serial_buf;
    struct serial_buf_entry serial_buf_data[SERIAL_BUF_SLOTS];

};

errval_t serialserver_add_client(struct aos_rpc *rpc, coreid_t mpid);

errval_t serialserver_serve_next(void);

errval_t serialserver_init(void
);

#endif
