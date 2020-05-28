/**
 * \file nameservice.h
 * \brief
 */

#ifndef INCLUDE_NAMESERVICE_H_
#define INCLUDE_NAMESERVICE_H_

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/deferred.h>
#include <rpc/server/ump.h>

#define NAMESERVICE_INIT "serverinit"
#define NAMESERVICE_PROCESS "serverprocess"
#define NAMESERVICE_MONITOR "servermonitor"
#define NAMESERVICE_SERIAL "serverserial"
#define NAMESERVICE_BLOCKDRIVER "serverblockdriver"
#define NAMESERVICE_FILESYSTEM "serverfilesystem"

#define NAMESERVICE_PERIODIC_SERVE_EVENT_US 10

typedef struct nameservice_chan* nameservice_chan_t;

struct nameservice_chan {
    const char *name;
    struct aos_rpc *rpc;
    domainid_t pid;
};

///< handler which is called when a message is received over the registered channel
typedef void(nameservice_receive_handler_t)(void *st,
										    void *message, size_t bytes,
										    void **response, size_t *response_bytes,
                                            struct capref tx_cap, struct capref *rx_cap);

struct srv_entry {
    char name[AOS_RPC_NAMESERVER_MAX_NAME_LENGTH + 1];
	nameservice_receive_handler_t *recv_handler;
	void *st;
    struct aos_rpc add_client_chan;
    struct rpc_ump_server ump_server;
    struct periodic_event periodic_urpc_ev;
};

/**
 * @brief sends a message back to the client who sent us a message
 *
 * @param chan opaque handle of the channel
 * @oaram message pointer to the message
 * @param bytes size of the message in bytes
 * @param response the response message
 * @param response_byts the size of the response
 *
 * @return error value
 */
errval_t nameservice_rpc(nameservice_chan_t chan, void *message, size_t bytes,
                         void **response, size_t *response_bytes,
                         struct capref tx_cap, struct capref rx_cap);



/**
 * @brief registers our selves as 'name'
 *
 * @param name  our name
 * @param recv_handler the message handler for messages received over this service
 * @param st  state passed to the receive handler
 *
 * @return SYS_ERR_OK
 */
errval_t nameservice_register(const char *name,
	                              nameservice_receive_handler_t recv_handler,
	                              void *st);

errval_t nameservice_register_at_chan(struct aos_rpc *rpc_chan, const char *name,
	                              nameservice_receive_handler_t recv_handler,
	                              void *st);

errval_t nameservice_register_no_send(const char *name,
	                              nameservice_receive_handler_t recv_handler,
	                              void *st);

/**
 * @brief deregisters the service 'name'
 *
 * @param the name to deregister
 *
 * @return error value
 */
errval_t nameservice_deregister(const char *name);


/**
 * @brief lookup an endpoint and obtain an RPC channel to that
 *
 * @param name  name to lookup
 * @param chan  pointer to the chan representation to send messages to the service
 *
 * @return  SYS_ERR_OK on success, errval on failure
 */
errval_t nameservice_lookup(const char *name, nameservice_chan_t *chan);


/**
 * @brief enumerates all entries that match an query (prefix match)
 *
 * @param query     the query
 * @param num 		number of entries in the result array
 * @param result	an array of entries
 */
errval_t nameservice_enumerate(char *query, size_t *num, char **result);


void nameservice_wait_for(char *name);
errval_t nameservice_wait_for_timeout(char *name, int n, delayus_t delay);

struct srv_entry *nameservice_get_entry(char *name);

#endif /* INCLUDE_AOS_AOS_NAMESERVICE_H_ */
