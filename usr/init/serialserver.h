#ifndef _USR_INIT_SERIALSERVER_H_
#define _USR_INIT_SERIALSERVER_H_

#include <aos/aos_rpc.h>

typedef void (* putchar_callback_t)(char c);
typedef void (* getchar_callback_t)(char *c);

errval_t serialserver_add_client(struct aos_rpc *rpc);

errval_t serialserver_serve_next(void);

errval_t serialserver_init(
    putchar_callback_t putchar_cb,
    getchar_callback_t getchar_cb
);

#endif
