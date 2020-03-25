#ifndef _USR_INIT_INITSERVER_H_
#define _USR_INIT_INITSERVER_H_

#include <aos/aos_rpc.h>

#define MAX_TOTAL_PAYLOAD_LENGTH 1024

typedef void (* recv_number_callback_t)(struct lmp_chan *, uint64_t numb);
typedef void (* recv_string_callback_t)(struct lmp_chan *, char *string);

enum pending_state {
    EmptyState = 0,
    StringTransmit = 1,
};

struct callback_state {
    struct aos_rpc rpc;
    uint32_t bytes_received; ///< How much was read from the client already.
    uint32_t total_length;
    enum pending_state pending_state;
    char *string;
};

errval_t initserver_init(recv_number_callback_t new_recv_number_cb, recv_string_callback_t new_recv_string_cb);

#endif
