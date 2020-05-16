/**
 * \file nameservice.h
 * \brief
 */
#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/waitset.h>
#include <aos/nameserver.h>
#include <aos/aos_rpc.h>


#include <hashtable/hashtable.h>


struct srv_entry {
	const char *name;
	nameservice_receive_handler_t *recv_handler;
	void *st;
};

struct nameservice_chan
{
	struct aos_rpc rpc;
	char *name;
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
                         struct capref tx_cap, struct capref rx_cap)
{
	return LIB_ERR_NOT_IMPLEMENTED;
}




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
	                              void *st)
{
    // TODO Initialize UMP server for the given name
    // TODO Create srv_entry and add to list
    // TODO Create serve function that goes through all srv_entries
    errval_t err;

    struct aos_rpc *monitor_chan = aos_rpc_lmp_get_monitor_channel();

    struct capref frame;

    err = frame_alloc(&frame, UMP_SHARED_FRAME_SIZE, NULL);
    if (err_is_fail(err)) {
        debug_printf("frame_alloc() failed: %s\n", err_getstring(err));
        return err;
    }

    struct aos_rpc *chan_add_client = malloc(sizeof(struct aos_rpc));

    err = aos_rpc_ump_init(chan_add_client, frame, true);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_init() failed: %s\n", err_getstring(err));
        return err;
    }

    // Send message to nameserver to register new service
    err = aos_rpc_ns_register(monitor_chan, name, chan_add_client);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_lmp_ns_register() failed: %s\n", err_getstring(err));
        return err;
    }

	return SYS_ERR_OK;
}


/**
 * @brief deregisters the service 'name'
 *
 * @param the name to deregister
 *
 * @return error value
 */
errval_t nameservice_deregister(const char *name)
{
	return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief lookup an endpoint and obtain an RPC channel to that
 *
 * @param name  name to lookup
 * @param chan  pointer to the chan representation to send messages to the service
 *
 * @return  SYS_ERR_OK on success, errval on failure
 */
errval_t nameservice_lookup(const char *name, nameservice_chan_t *nschan)
{
	return LIB_ERR_NOT_IMPLEMENTED;
}


/**
 * @brief enumerates all entries that match an query (prefix match)
 *
 * @param query     the query
 * @param num 		number of entries in the result array
 * @param result	an array of entries
 */
errval_t nameservice_enumerate(char *query, size_t *num, char **result )
{
	return LIB_ERR_NOT_IMPLEMENTED;
}

