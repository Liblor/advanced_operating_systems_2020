#ifndef BF_AOS_URPC_H
#define BF_AOS_URPC_H

#include <aos/aos.h>

#define URPC_SHARED_MEM_SIZE 4*BASE_PAGE_SIZE

enum urpc_status {
    Empty,
    ServerData,     // core 1 is server
    ClientData,     // core 0 is client
};

enum urpc_msg_type {
    BootInfo,
    SpawnRequest,
    SpawnResponse
};

struct urpc_spawn_request {
    uint64_t name_len;
    uint64_t cmdline_len;
    char args[0];
};

struct urpc_spawn_response {
    errval_t err;
    domainid_t newpid;
};

struct urpc_shared_mem {
    enum urpc_msg_type type;
    enum urpc_status status;

    union {
        struct bootinfo bi;
        struct urpc_spawn_request spawn_req;
        struct urpc_spawn_response spawn_resp;
    };
};

errval_t urpc_init(void);
errval_t urpc_send_boot_info(void);

#endif //BF_AOS_URPC_H
