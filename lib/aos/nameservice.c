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
#include <aos/deferred.h>

#include <rpc/server/ump.h>

#include <hashtable/hashtable.h>


collections_listnode *service_list_head = NULL;

static errval_t serve_add_client(struct srv_entry *service) {
    errval_t err;

    assert(service != NULL);

    // TODO Allocate message on stack
    struct rpc_message *msg = NULL;

    err = aos_rpc_ump_receive_non_block(&service->add_client_chan, &msg);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_receive_non_block() failed: %s\n", err_getstring(err));
        return err;
    }

    // Check if a message has been received
    if (msg != NULL) {
        assert(msg->msg.method == Method_Ump_Add_Client);
        assert(msg->msg.status == Status_Ok);
        assert(msg->msg.payload_length == 0);
        assert(capref_is_null(msg->cap));

        // Create new channel for client
        struct capref frame;

        err = frame_alloc(&frame, UMP_SHARED_FRAME_SIZE, NULL);
        if (err_is_fail(err)) {
            debug_printf("frame_alloc() failed: %s\n", err_getstring(err));
            return err;
        }

        struct aos_rpc *client_chan = malloc(sizeof(struct aos_rpc));
        if (client_chan == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }

        err = aos_rpc_ump_init(client_chan, frame, true);
        if (err_is_fail(err)) {
            debug_printf("aos_rpc_ump_init() failed: %s\n", err_getstring(err));
            return err;
        }

        // Add channel to UMP server
        err = rpc_ump_server_add_client(&service->ump_server, client_chan);
        if (err_is_fail(err)) {
            debug_printf("rpc_ump_server_add_client() failed: %s\n", err_getstring(err));
            return err;
        }

        // Reply with newly created client channel
        uint8_t send_buf[sizeof(struct rpc_message)];
        struct rpc_message *reply = (struct rpc_message *) &send_buf;

        reply->msg.method = Method_Ump_Add_Client;
        reply->msg.payload_length = 0;
        reply->msg.status = Status_Ok;
        reply->cap = frame;

        err = aos_rpc_ump_send_message(&service->add_client_chan, reply);
        if (err_is_fail(err)) {
            debug_printf("aos_rpc_ump_send_message() failed: %s\n", err_getstring(err));
            return err;
        }
    }

    return SYS_ERR_OK;
}

static int nameservice_serve(void *arg)
{
    errval_t err;

    struct srv_entry *service = arg;

    // Serve regular client requests
    err = rpc_ump_server_serve_next(&service->ump_server);
    if (err_is_fail(err)) {
        debug_printf("Error when calling rpc_ump_server_serve_next() for service '%s': %s\n", service->name, err_getstring(err));
        return 1;
    }

    // Serve client add request from the nameserver
    err = serve_add_client(service);
    if (err_is_fail(err)) {
        debug_printf("serve_add_client() failed: %s\n", err_getstring(err));
        return 1;
    }

    return 0;
}

static void service_periodic_event_func(void *arg)
{
    nameservice_serve(arg);
}

__unused
static int service_thread_func(void *arg)
{
    while (true) {
        int ret =  nameservice_serve(arg);
        if (ret != 0) {
            return ret;
        }

        thread_yield();
    }

    return 1;
}

static void service_recv_cb(struct rpc_message *msg, void *callback_state, struct aos_rpc *rpc, void *server_state)
{
    errval_t err;

    assert(msg->msg.status == Status_Ok);
    assert(msg->msg.method == Method_Nameserver_Service_Request);

    struct srv_entry *service = server_state;

    void *st = service->st;
    void *message = msg->msg.payload;
    size_t bytes = sizeof(struct rpc_message) + msg->msg.payload_length;
    struct capref rx_cap = msg->cap;

    void *response = NULL;
    size_t response_bytes = 0;
    struct capref tx_cap = NULL_CAP;

    // Call callback to construct response
    service->recv_handler(st, message, bytes, &response, &response_bytes, rx_cap, &tx_cap);

    if (response != NULL && response_bytes > 0) {
        // Send response
        uint8_t send_buf[sizeof(struct rpc_message) + response_bytes];
        struct rpc_message *send = (struct rpc_message *) &send_buf;
        send->msg.method = Method_Nameserver_Service_Response;
        send->msg.payload_length = response_bytes;
        send->msg.status = Status_Ok;
        send->cap = tx_cap;
        memcpy(send->msg.payload, response, response_bytes);

        err = aos_rpc_ump_send_message(rpc, send);
        if (err_is_fail(err)) {
            debug_printf("aos_rpc_ump_send_message() failed: %s\n", err_getstring(err));
            return;
        }
    }

    free(response);
}

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
// TODO All callers have to free the response
errval_t nameservice_rpc(nameservice_chan_t chan, void *message, size_t bytes,
                         void **response, size_t *response_bytes,
                         struct capref tx_cap, struct capref rx_cap)
{
    errval_t err;

    assert(chan != NULL);
    assert(message != NULL);

    struct aos_rpc *rpc = chan->rpc;

    uint8_t send_buf[sizeof(struct rpc_message) + bytes];
    struct rpc_message *send = (struct rpc_message *) &send_buf;
    send->msg.method = Method_Nameserver_Service_Request;
    send->msg.payload_length = bytes;
    send->msg.status = Status_Ok;
    send->cap = tx_cap;
    memcpy(send->msg.payload, message, bytes);

    struct rpc_message *recv = NULL;

    if (response != NULL && response_bytes != NULL) {
        err = aos_rpc_ump_send_and_wait_recv(rpc, send, &recv);
        if (err_is_fail(err)) {
            free(recv);
            return err;
        }
        *response_bytes = recv->msg.payload_length;
        *response = calloc(1, recv->msg.payload_length);
        if (*response == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        memcpy(*response, &recv->msg.payload, *response_bytes);
        if (!capref_is_null(rx_cap)) {
            cap_copy(rx_cap, recv->cap);
        }
        free(recv);
    } else {
        err = aos_rpc_ump_send_message(rpc, send);
        if (err_is_fail(err)) {
            return err;
        }
    }

    return SYS_ERR_OK;
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
    struct aos_rpc *monitor_chan = aos_rpc_lmp_get_monitor_channel();

    return nameservice_register_at_chan(monitor_chan, name, recv_handler, st);
}

errval_t nameservice_register_at_chan(struct aos_rpc *rpc_chan, const char *name,
	                              nameservice_receive_handler_t recv_handler,
	                              void *st)
{
    errval_t err;

    if (service_list_head == NULL) {
        collections_list_create(&service_list_head, NULL);
    }

    struct srv_entry *service = malloc(sizeof(struct srv_entry));
    if (service == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    struct capref frame;

    err = frame_alloc(&frame, UMP_SHARED_FRAME_SIZE, NULL);
    if (err_is_fail(err)) {
        debug_printf("frame_alloc() failed: %s\n", err_getstring(err));
        return err;
    }

    err = aos_rpc_ump_init(&service->add_client_chan, frame, true);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_init() failed: %s\n", err_getstring(err));
        return err;
    }

    if (rpc_chan != NULL) {
        domainid_t pid = disp_get_domain_id();

        // Send message to nameserver to register new service
        err = aos_rpc_ns_register(rpc_chan, name, &service->add_client_chan, pid);
        if (err_is_fail(err)) {
            debug_printf("aos_rpc_lmp_ns_register() failed: %s\n", err_getstring(err));
            return err;
        }
    }

    memset(service->name, 0, sizeof(service->name));
    strncpy(service->name, name, AOS_RPC_NAMESERVER_MAX_NAME_LENGTH);
    service->recv_handler = recv_handler;
    service->st = st;

    err = rpc_ump_server_init(&service->ump_server, service_recv_cb, NULL, NULL, service);
    if (err_is_fail(err)) {
        debug_printf("rpc_ump_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    memset(&service->periodic_urpc_ev, 0, sizeof(struct periodic_event));

    err = periodic_event_create(&service->periodic_urpc_ev,
                                get_default_waitset(),
                                NAMESERVICE_PERIODIC_SERVE_EVENT_US,
                                MKCLOSURE(service_periodic_event_func, service));

    int32_t ret = collections_list_insert(service_list_head, service);
    assert(ret == 0);

	return SYS_ERR_OK;
}

errval_t nameservice_register_no_send(const char *name,
	                              nameservice_receive_handler_t recv_handler,
	                              void *st)
{
    return nameservice_register_at_chan(NULL, name, recv_handler, st);
}

static int32_t service_has_name(void *data, void *arg)
{
    struct srv_entry *service = data;
    const char *name = arg;

    return strcmp(service->name, name) == 0;
}

struct srv_entry *nameservice_get_entry(char *name) {
    assert(name != NULL);
    assert(service_list_head != NULL);

    return (struct srv_entry *) collections_list_find_if(service_list_head, service_has_name, (void *) name);
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
    errval_t err;

    struct aos_rpc *monitor_chan = aos_rpc_lmp_get_monitor_channel();

    struct srv_entry *service = collections_list_remove_if(service_list_head, service_has_name, (void *) name);
    if (service == NULL) {
        debug_printf("Service '%s' has not been registered by this process.", name);
        // TODO Proper error
        return LIB_ERR_NOT_IMPLEMENTED;
    }

    // TODO Clean up local data structures that were created by nameservice_register():
    // TODO Free add_client_chan and the frame it uses
    // TODO Terminate and free service_thread
    // TODO Free st (?)
    // TODO free ump_server
    // TODO What happens to processes that got the now non-existant server in a lookup?

    err = aos_rpc_ns_deregister(monitor_chan, name);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ns_deregister() failed: %s\n", err_getstring(err));
        return err;
    }
	return SYS_ERR_OK;
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
    errval_t err;

    struct aos_rpc *monitor_chan = aos_rpc_lmp_get_monitor_channel();

    // TODO Maybe have a single aos_rpc statically available to lookup the memory server
    struct aos_rpc *rpc = malloc(sizeof(struct aos_rpc));
    struct nameservice_chan *service_chan = malloc(sizeof(struct nameservice_chan));
    if (service_chan == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    domainid_t pid;
    err = aos_rpc_ns_lookup(monitor_chan, name, rpc, &pid);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ns_lookup() failed: %s\n", err_getstring(err));
        return err;
    }

    assert(rpc->type == RpcTypeUmp);

    service_chan->name = name;
    service_chan->rpc = rpc;
    service_chan->pid = pid;

    *nschan = service_chan;

	return SYS_ERR_OK;
}


/**
 * @brief enumerates all entries that match an query (prefix match)
 *
 * @param query     the query
 * @param num 		number of entries in the result array
 * @param result	an array of entries
 */
errval_t nameservice_enumerate(char *query, size_t *num, char **result)
{
    errval_t err;

    struct aos_rpc *monitor_chan = aos_rpc_lmp_get_monitor_channel();

    err = aos_rpc_ns_enumerate(monitor_chan, query, num, result);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ns_enumerate() failed: %s\n", err_getstring(err));
        return err;
    }

	return SYS_ERR_OK;
}


void nameservice_wait_for(char *name)
{
    errval_t err;
    nameservice_chan_t chan;
    do {
        err = nameservice_lookup(name, &chan);
        thread_yield();
    } while(err_is_fail(err));
    free(chan);
}

errval_t nameservice_wait_for_timeout(char *name, int n, delayus_t delay)
{
    errval_t err;
    nameservice_chan_t chan;
    int c = 0;
    do {
        err = nameservice_lookup(name, &chan);
        barrelfish_usleep(delay);
        thread_yield();
        c++;
    } while(c < n && err_is_fail(err));
    if (err_is_ok(err)) {
        free(chan);
    }
    return err;
}
