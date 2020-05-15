#ifndef _USR_INIT_SERIALSERVER_H_
#define _USR_INIT_SERIALSERVER_H_

#include <aos/aos_rpc.h>

errval_t serialserver_add_client(struct aos_rpc *rpc, coreid_t mpid);

errval_t serialserver_serve_next(void);

errval_t serialserver_init(void
);

#endif
