#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>

#include <rpc/server/ump.h>


errval_t rpc_ump_server_serve_next(struct rpc_ump_server *server)
{
    errval_t err;

    if (server->client_count != 0 && !server->processing_paused) {
        struct aos_rpc *curr;

        int32_t ret = collections_list_traverse_start(server->client_list);
        assert(ret == 1);

        while ((curr = collections_list_traverse_next(server->client_list)) != NULL) {
            // Try to receive a new message
            struct rpc_message *msg = NULL;
            err = aos_rpc_ump_receive_non_block(curr, &msg);
            if (err_is_fail(err)) {
                debug_printf("aos_rpc_ump_receive_non_block() failed: %s\n", err_getstring(err));
                return err;
            }

            // Check if a message has been received
            if (msg != NULL) {
                if (server->service_recv_handler != NULL) {
                    server->service_recv_handler(msg, NULL, curr, server->shared);
                }
            }

            // Increase counter so that another client will be served on the next call
            server->client_next++;
            server->client_next %= server->client_count;
            free(msg);
        }

        ret = collections_list_traverse_end(server->client_list);
        assert(ret == 1);

    }

    return SYS_ERR_OK;
}

errval_t rpc_ump_server_add_client(struct rpc_ump_server *server, struct aos_rpc *rpc)
{
    int32_t res = collections_list_insert(server->client_list, rpc);
    if (res != 0) {
        // TODO Return error
        assert(false);
    }

    server->client_count++;

    return SYS_ERR_OK;
}

void rpc_ump_server_pause_processing(struct rpc_ump_server *server)
{
    server->processing_paused = true;
}

void rpc_ump_server_start_processing(struct rpc_ump_server *server)
{
    server->processing_paused = false;
}

// Initialize the server.
errval_t rpc_ump_server_init(
    struct rpc_ump_server *server,
    service_recv_handler_t new_service_recv_handler,
    state_init_handler_t new_state_init_handler,
    state_free_handler_t new_state_free_handler,
    void *server_state
)
{
    server->service_recv_handler = new_service_recv_handler;
    // TODO Remove those handlers if we don't need a state per client
    server->state_init_handler = new_state_init_handler;
    server->state_free_handler = new_state_free_handler;
    server->processing_paused = false;
    server->shared = server_state;

    collections_list_create(&server->client_list, NULL);
    server->client_count = 0;
    server->client_next = 0;

    return SYS_ERR_OK;
}
