#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_ump.h>
#include <aos/aos_rpc_types.h>
#include <aos/domain.h>
#include <ctype.h>

#include <rpc/server/ump.h>

#include "nameserver.h"

static struct rpc_ump_server server;

#define NAMESERVER_STATUS_RESPONSE_SIZE (sizeof(struct rpc_message) + 0)
#define NAMESERVER_REGISTER_RESPONSE_SIZE (NAMESERVER_STATUS_RESPONSE_SIZE)
#define NAMESERVER_DEREGISTER_RESPONSE_SIZE (NAMESERVER_STATUS_RESPONSE_SIZE)
#define NAMESERVER_LOOKUP_RESPONSE_SIZE (NAMESERVER_STATUS_RESPONSE_SIZE + sizeof(domainid_t))
#define NAMESERVER_ENUMERATE_RESPONSE_SIZE (NAMESERVER_STATUS_RESPONSE_SIZE)

struct nameserver_entry {
	char name[AOS_RPC_NAMESERVER_MAX_NAME_LENGTH + 1];
    struct aos_rpc add_client_chan;
    domainid_t pid;
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

static void read_name(char dst[AOS_RPC_NAMESERVER_MAX_NAME_LENGTH + 1], struct rpc_message *msg)
{
    memset(dst, 0, AOS_RPC_NAMESERVER_MAX_NAME_LENGTH + 1);
    memcpy(dst, msg->msg.payload, AOS_RPC_NAMESERVER_MAX_NAME_LENGTH);
}

static void reply_init(struct rpc_message *msg, struct rpc_message *resp)
{
    resp->msg.method = msg->msg.method;
    resp->msg.status = Status_Ok;
    resp->msg.payload_length = 0;
    resp->cap = NULL_CAP;
}

static bool check_name_valid(char *name)
{
    for (char *ptr = name; *ptr != '\0'; ptr++) {
        if (!(isalnum(*ptr) || *ptr == '/')) {
            return false;
        }
    }

    return true;
}

static void handle_register(struct rpc_message *msg, struct nameserver_state *ns_state, struct rpc_message *resp)
{
    errval_t err;

    assert(msg != NULL);
    assert(ns_state != NULL);

    char name[AOS_RPC_NAMESERVER_MAX_NAME_LENGTH + 1];
    read_name(name, msg);

    domainid_t pid;
    memcpy(&pid, &(msg->msg.payload[AOS_RPC_NAMESERVER_MAX_NAME_LENGTH]), sizeof(domainid_t));

    if (!check_name_valid(name)) {
        debug_printf("Service name '%s' is not allowed.\n", name);
        resp->msg.status = Status_Error;
        return;
    }

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

    entry->pid = pid;
    strncpy(entry->name, name, AOS_RPC_NAMESERVER_MAX_NAME_LENGTH);

    err = aos_rpc_ump_init(&entry->add_client_chan, chan_frame_cap, false);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_init() failed: %s", err_getstring(err));
        resp->msg.status = Status_Error;
        return;
    }

    collections_hash_insert(service_table, hash, entry);
}

static void handle_deregister(struct rpc_message *msg, struct nameserver_state *ns_state, struct rpc_message *resp)
{
    assert(msg != NULL);
    assert(ns_state != NULL);

    char name[AOS_RPC_NAMESERVER_MAX_NAME_LENGTH + 1];
    read_name(name, msg);

    collections_hash_table *service_table = ns_state->service_table;
    assert(service_table != NULL);

    uint64_t hash = hash_string(name);
    struct nameserver_entry *entry = collections_hash_find(service_table, hash);

    if (entry == NULL) {
        debug_printf("Service '%s' not registered.\n", name);
        resp->msg.status = Status_Error;
        return;
    }

    debug_printf("Removing service '%s' from service table.\n", name);

    collections_hash_delete(service_table, hash);
}

static errval_t send_add_client(struct aos_rpc *add_client_chan, struct capref *ret_frame_cap)
{
    errval_t err;

    uint8_t send_buf[sizeof(struct rpc_message)];
    struct rpc_message *send = (struct rpc_message *) &send_buf;

    send->msg.method = Method_Ump_Add_Client;
    send->msg.payload_length = 0;
    send->msg.status = Status_Ok;
    send->cap = NULL_CAP;

    uint8_t recv_buf[sizeof(struct rpc_message)];
    struct rpc_message *recv = (struct rpc_message *) &recv_buf;
    // Allocate slot for receive message since we will receive a frame capability here
    err = slot_alloc(&recv->cap);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc() failed: %s\n", err_getstring(err));
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    err = aos_rpc_ump_send_and_wait_recv(add_client_chan, send, &recv);
    if (err_is_fail(err)) {
        debug_printf("aos_rpc_ump_send_and_wait_recv() failed: %s", err_getstring(err));
        return err;
    }

    assert(recv->msg.method == Method_Ump_Add_Client);
    assert(recv->msg.status == Status_Ok);
    assert(recv->msg.payload_length == 0);
    assert(!capref_is_null(recv->cap));

    *ret_frame_cap = recv->cap;

    return SYS_ERR_OK;
}

static void handle_lookup(struct rpc_message *msg, struct nameserver_state *ns_state, struct rpc_message *resp)
{
    errval_t err;

    assert(msg != NULL);
    assert(ns_state != NULL);

    char name[AOS_RPC_NAMESERVER_MAX_NAME_LENGTH + 1];
    read_name(name, msg);

    collections_hash_table *service_table = ns_state->service_table;
    assert(service_table != NULL);

    uint64_t hash = hash_string(name);
    struct nameserver_entry *entry = collections_hash_find(service_table, hash);

    if (entry == NULL) {
        debug_printf("Service '%s' not registered.\n", name);
        resp->msg.status = Status_Error;
        return;
    }

    struct capref client_frame_cap;

    err = send_add_client(&entry->add_client_chan, &client_frame_cap);
    if (err_is_fail(err)) {
        debug_printf("send_add_client() failed: %s", err_getstring(err));
        resp->msg.status = Status_Error;
        return;
    }

    resp->msg.payload_length = sizeof(domainid_t);
    memcpy(resp->msg.payload, &entry->pid, sizeof(domainid_t));
    resp->cap = client_frame_cap;
}

static bool query_matches(char *query, char *name)
{
    // Check if name starts with query
    return strncmp(query, name, strlen(query)) == 0;
}

static void handle_enumerate(struct rpc_message *msg, struct nameserver_state *ns_state, struct rpc_message **resp)
{
    int32_t ret;

    assert(msg != NULL);
    assert(ns_state != NULL);

    char query[AOS_RPC_NAMESERVER_MAX_NAME_LENGTH + 1];
    read_name(query, msg);

    collections_hash_table *service_table = ns_state->service_table;
    assert(service_table != NULL);

    // Count entries that match the received query
    size_t name_list_len = 0;
    size_t match_count = 0;
    __unused uint64_t key;
    struct nameserver_entry *entry;

    ret = collections_hash_traverse_start(service_table);
    assert(ret == 1);
    while ((entry = collections_hash_traverse_next(service_table, &key))) {
        if (query_matches(query, entry->name)) {
            size_t name_len = strlen(entry->name);
            name_list_len += name_len + 1; // Add one for null-byte
            match_count++;
        }
    }
    ret = collections_hash_traverse_end(service_table);
    assert(ret == 1);

    // Allocate buffer large enough to contain all matches
    size_t payload_length = sizeof(size_t) + name_list_len;
    *resp = malloc(NAMESERVER_ENUMERATE_RESPONSE_SIZE + payload_length);
    reply_init(msg, *resp);
    (*resp)->msg.payload_length = payload_length;

    // Write matches into response
    char * const payload_base = &((*resp)->msg.payload[0]);
    char *ptr = payload_base;
    memcpy(ptr, &match_count, sizeof(size_t));
    ptr += sizeof(size_t);

    ret = collections_hash_traverse_start(service_table);
    assert(ret == 1);
    while ((entry = collections_hash_traverse_next(service_table, &key))) {
        if (query_matches(query, entry->name)) {
            size_t name_len = strlen(entry->name);
            // Add one for null-byte
            memcpy(ptr, entry->name, name_len + 1);
            ptr += name_len + 1;
        }
    }
    assert(((void *) ptr) - ((void *) payload_base) == payload_length);
    ret = collections_hash_traverse_end(service_table);
    assert(ret == 1);
}

static void service_recv_cb(struct rpc_message *msg, void *callback_state, struct aos_rpc *rpc, void *server_state)
{
    errval_t err;

    struct nameserver_state *ns_state = server_state;
    struct rpc_message *resp;

	switch (msg->msg.method) {
    case Method_Nameserver_Register:
        resp = malloc(NAMESERVER_REGISTER_RESPONSE_SIZE);
        reply_init(msg, resp);

        handle_register(msg, ns_state, resp);
        break;
    case Method_Nameserver_Deregister:
        resp = malloc(NAMESERVER_DEREGISTER_RESPONSE_SIZE);
        reply_init(msg, resp);

        handle_deregister(msg, ns_state, resp);
        break;
    case Method_Nameserver_Lookup:
        resp = malloc(NAMESERVER_LOOKUP_RESPONSE_SIZE);
        reply_init(msg, resp);

        handle_lookup(msg, ns_state, resp);
        break;
    case Method_Nameserver_Enumerate:
        handle_enumerate(msg, ns_state, &resp);
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

static int nameserver_thread_func(void *arg)
{
    errval_t err;

    debug_printf("Serving nameserver requests.\n");

    while (true) {
        err = nameserver_serve_next();
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "in nameserver_ump_serve_next");
            return 1;
        }

        thread_yield();
    }

    return 0;
}

void nameserver_serve_in_thread(struct nameserver_state *server_state)
{
    struct thread *nameserver_thread = thread_create(nameserver_thread_func, server_state);

    assert(nameserver_thread != NULL);
}
