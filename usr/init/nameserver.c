#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>
#include <aos/aos_rpc_types.h>

#include <rpc/server/ump.h>

#include "nameserver.h"

static struct rpc_ump_server server;

#define NAMESERVER_STATUS_RESPONSE_SIZE (sizeof(struct rpc_message) + 0)
#define NAMESERVER_REGISTER_RESPONSE_SIZE (NAMESERVER_STATUS_RESPONSE_SIZE)
#define NAMESERVER_DEREGISTER_RESPONSE_SIZE (NAMESERVER_STATUS_RESPONSE_SIZE)
#define NAMESERVER_LOOKUP_RESPONSE_SIZE (NAMESERVER_STATUS_RESPONSE_SIZE)
#define NAMESERVER_ENUMERATE_RESPONSE_SIZE (NAMESERVER_STATUS_RESPONSE_SIZE)

struct nameserver_entry {
	char name[AOS_RPC_NAMESERVER_MAX_NAME_LENGTH + 1];
    struct aos_rpc add_client_chan;
};

// Source: http://www.cse.yorku.ca/~oz/hash.html
static uint64_t hash_string(char *str)
{
    assert(str != NULL);

    uint64_t hash = 5381;
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

static void handle_register(struct rpc_message *msg, struct nameserver_state *ns_state, struct rpc_message *resp)
{
    errval_t err;

    assert(msg != NULL);
    assert(ns_state != NULL);

    char name[AOS_RPC_NAMESERVER_MAX_NAME_LENGTH + 1];
    memset(name, 0, AOS_RPC_NAMESERVER_MAX_NAME_LENGTH + 1);
    memcpy(name, msg->msg.payload, AOS_RPC_NAMESERVER_MAX_NAME_LENGTH);

    struct capref chan_frame_cap = msg->cap;

    collections_hash_table *service_table = ns_state->service_table;
    assert(service_table != NULL);

    uint64_t hash = hash_string(name);
    struct nameserver_entry *entry = collections_hash_find(service_table, hash);

    if (entry != NULL) {
        debug_printf("Service '%s' already registered.\n", name);
        resp->msg.status = Status_Error;
        return;
    }

    debug_printf("Adding new service '%s' to service table.\n", name);

    entry = calloc(1, sizeof(struct nameserver_entry));
    if (entry == NULL) {
        debug_printf("calloc() failed");
        resp->msg.status = Status_Error;
        return;
    }

    strncpy(entry->name, name, AOS_RPC_NAMESERVER_MAX_NAME_LENGTH);

    debug_dump_cap_at_capref(chan_frame_cap);
    err = aos_rpc_ump_init(&entry->add_client_chan, chan_frame_cap, false);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_init() failed: %s", err_getstring(err));
        resp->msg.status = Status_Error;
        return;
    }

    collections_hash_insert(service_table, hash, entry);
}

static void reply_init(struct rpc_message *msg, struct rpc_message *resp)
{
    resp->msg.method = msg->msg.method;
    resp->msg.status = Status_Ok;
    resp->msg.payload_length = 0;
    resp->cap = NULL_CAP;
}

static void service_recv_cb(struct rpc_message *msg, void *callback_state, struct aos_rpc *rpc, void *server_state)
{
    errval_t err;

    struct nameserver_state *ns_state = server_state;
    struct rpc_message *resp;

	switch (msg->msg.method) {
    case Method_Nameserver_Register:
        debug_printf("Method_Nameserver_Register\n");
        debug_dump_cap_at_capref(msg->cap);

        resp = malloc(NAMESERVER_REGISTER_RESPONSE_SIZE);
        reply_init(msg, resp);

        handle_register(msg, ns_state, resp);
        break;
    case Method_Nameserver_Deregister:
        debug_printf("Method_Nameserver_Deregister\n");
        resp = malloc(NAMESERVER_DEREGISTER_RESPONSE_SIZE);
        reply_init(msg, resp);
        break;
    case Method_Nameserver_Lookup:
        debug_printf("Method_Nameserver_Lookup\n");
        resp = malloc(NAMESERVER_LOOKUP_RESPONSE_SIZE);
        reply_init(msg, resp);
        break;
    case Method_Nameserver_Enumerate:
        debug_printf("Method_Nameserver_Enumerate\n");
        resp = malloc(NAMESERVER_ENUMERATE_RESPONSE_SIZE);
        reply_init(msg, resp);
        break;
    default:
        debug_printf("Unknown message type. Ignoring message.\n");
        resp = malloc(NAMESERVER_STATUS_RESPONSE_SIZE);
        reply_init(msg, resp);
        resp->msg.status = Status_Error;
        break;
	}

    err = aos_rpc_ump_send_message(rpc, resp);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_send_message() failed: %s", err_getstring(err));
    }
}

errval_t nameserver_add_client(struct aos_rpc *rpc, coreid_t mpid)
{
    return rpc_ump_server_add_client(&server, rpc);
}

errval_t nameserver_serve_next(void)
{
    return rpc_ump_server_serve_next(&server);
}

static void free_nameserver_entry(void *ns_entry)
{
    struct nameserver_entry *entry = ns_entry;

    // TODO Free memebers of entry

    free(entry);
}

errval_t nameserver_init(struct nameserver_state *server_state)
{
    errval_t err;

    collections_hash_create(&server_state->service_table, free_nameserver_entry);

    err = rpc_ump_server_init(&server, service_recv_cb, NULL, NULL, server_state);
    if (err_is_fail(err)) {
        debug_printf("rpc_ump_server_init() failed: %s\n", err_getstring(err));
        return err_push(err, RPC_ERR_INITIALIZATION);
    }

    debug_printf("Namerserver started.\n");
    return SYS_ERR_OK;
}
