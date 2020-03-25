#ifndef _USR_INIT_PROCESSSERVER_H_
#define _USR_INIT_PROCESSSERVER_H_

#include <aos/aos_rpc.h>

typedef void (* spawn_callback_t)(void);
typedef void (* get_name_callback_t)(void);
typedef void (* get_all_pids_callback_t)(void);

struct processserver_cb_state {
};

errval_t processserver_init(
    spawn_callback_t spawn_cb,
    get_name_callback_t get_name_cb,
    get_all_pids_callback_t get_all_pids_cb
);

#endif
