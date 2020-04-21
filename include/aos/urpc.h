#ifndef BF_AOS_URPC_H
#define BF_AOS_URPC_H

#include <aos/aos.h>

#define URPC_SHARED_MEM_SIZE 4*BASE_PAGE_SIZE

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

struct bootinfo_msg {
    genpaddr_t mmstring_base;
    gensize_t mmstring_size;
    struct bootinfo bi;
};

struct urpc_spawn_request {
    // TODO: rename to cmdline_size
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
        //struct bootinfo bi;
        struct bootinfo_msg bootinfo_msg;
        struct urpc_spawn_request spawn_req;
        struct urpc_spawn_response spawn_resp;
    };
};

errval_t master_urpc_init(void);
errval_t urpc_send_boot_info(struct bootinfo *bi);
errval_t urpc_send_spawn_request(char *cmdline, coreid_t core, domainid_t *newpid);

errval_t urpc_slave_init(void);
errval_t urpc_receive_bootinfo(void);
errval_t urpc_slave_serve_req(void);

typedef errval_t (* urpc_slave_spawn_process_cb)(char *cmdline, domainid_t *ret_pid);
typedef errval_t (* urpc_slave_init_memsys_cb) (
        struct bootinfo *b,
        genpaddr_t mmstring_base,
        gensize_t mmstring_size
);

extern urpc_slave_spawn_process_cb urpc_slave_spawn_process;
extern urpc_slave_init_memsys_cb urpc_slave_init_memsys;


#endif //BF_AOS_URPC_H
