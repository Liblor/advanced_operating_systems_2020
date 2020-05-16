#ifndef _USR_INIT_NAMESERVER_H_
#define _USR_INIT_NAMESERVER_H_

#include <aos/aos_rpc.h>

struct nameserver_state {
    collections_hash_table *service_table;
};

errval_t nameserver_add_client(struct aos_rpc *rpc, coreid_t mpid);

errval_t nameserver_serve_next(void);

errval_t nameserver_init(struct nameserver_state *server_state);

#endif
