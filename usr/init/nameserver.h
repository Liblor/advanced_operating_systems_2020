#ifndef _USR_INIT_NAMESERVER_H_
#define _USR_INIT_NAMESERVER_H_

#include <aos/aos_rpc.h>
#include <aos/deferred.h>

#define NAMESERVER_PERIODIC_SERVE_EVENT_US 50

struct nameserver_state {
    collections_hash_table *service_table;

    struct periodic_event add_client_response_periodic_ev;
    struct aos_rpc *rpc_add_client_request_pending;
    struct aos_rpc *rpc_add_client_response_pending;
    domainid_t add_client_pid_pending;
};

errval_t nameserver_add_client(struct aos_rpc *rpc, coreid_t mpid);

errval_t nameserver_serve_next(void);

errval_t nameserver_init(struct nameserver_state *server_state);

errval_t nameserver_add_service(struct nameserver_state *ns_state, char *name, struct capref chan_frame_cap, domainid_t pid);

void nameserver_serve_in_thread(struct nameserver_state *server_state);

#endif
