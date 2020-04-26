#ifndef _USR_INIT_INITSERVER_H_
#define _USR_INIT_INITSERVER_H_

#include <aos/aos_rpc.h>

#define MAX_TOTAL_PAYLOAD_LENGTH 1024

typedef void (* recv_number_callback_t)(uint64_t numb);
typedef void (* recv_string_callback_t)(char *string);

struct initserver_cb_state {
};

errval_t initserver_init(
    recv_number_callback_t recv_number_cb,
    recv_string_callback_t recv_string_cb
);

#endif
