#ifndef _USR_INIT_SERIALSERVER_H_
#define _USR_INIT_SERIALSERVER_H_

#include <aos/aos_rpc.h>



#define SERIAL_SERVER_DEBUG_ON

#if defined(SERIAL_SERVER_DEBUG_ON)
#define SERIAL_SERVER_DEBUG(x...) debug_printf("serial-server:" x)
#else
#define SERIAL_SERVER_DEBUG(x...) ((void)0)
#endif

// enable to use kernel functions instead of userspace
// #define SERIAL_SERVER_USE_KERNEL

#define READ_DATA_SLOTS 256

struct serial_read_slot {
    char val;
};

struct serial_read_data {
    bool full;
    size_t head;
    size_t tail;
    struct serial_read_slot data[READ_DATA_SLOTS];
};

struct serialserver_state {
    // struct serial_read_data ring_buffer;
    serial_session_t curr_read_session;
    struct aos_rpc * deferred_rpc;

};

errval_t serialserver_add_client(struct aos_rpc *rpc, coreid_t mpid);

errval_t serialserver_serve_next(void);

errval_t serialserver_init(void
);

#endif
