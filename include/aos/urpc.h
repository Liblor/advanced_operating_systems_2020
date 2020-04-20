#ifndef BF_AOS_URPC_H
#define BF_AOS_URPC_H

#include <aos/aos.h>

enum urpc_status {
    UrpcEmpty,
    UrpcWritting,
    UrpcMasterData,
    UrpcSlaveData,
};

enum urpc_msg_type {
    BootInfo,
    SpawnRequest,
    SpawnResponse
};

struct urpc_spawn_request {
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

errval_t urpc_slave_serve_req(void);

typedef errval_t (* urpc_slave_spawn_process_cb)(char *cmdline, domainid_t *ret_pid);
typedef errval_t (* urpc_slave_init_memsys_cb) (struct bootinfo *b);

extern urpc_slave_spawn_process_cb urpc_slave_spawn_process;
extern urpc_slave_init_memsys_cb urpc_slave_init_memsys;



#endif //BF_AOS_URPC_H
