#ifndef _USR_INIT_SERIALSERVER_H_
#define _USR_INIT_SERIALSERVER_H_

#include <aos/aos_rpc.h>

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

errval_t serialserver_add_client(struct aos_rpc *rpc, coreid_t mpid);

errval_t serialserver_serve_next(void);

errval_t serialserver_init(void
);

#endif
