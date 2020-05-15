#ifndef _LIB_BARRELFISH_AOS_RPC_TYPES_H
#define _LIB_BARRELFISH_AOS_RPC_TYPES_H

#include <aos/aos.h>

// TODO: Assign explicit numbers.
enum rpc_message_method {
    Method_Send_Bootinfo,
    Method_Send_Binding,
    Method_Send_Number,
    Method_Get_Ram_Cap,
    Method_Send_String,
    Method_Serial_Putchar,
    Method_Serial_Getchar,
    Method_Process_Get_Name,
    Method_Process_Get_All_Pids,
    Method_Spawn_Process,
    Method_Localtask_Spawn_Process
};

enum rpc_message_status {
    Status_Ok = 0,
    Spawn_Failed = 1,
    Process_Get_Name_Failed = 2,
    Process_Get_All_Pids_Failed = 3,
    Status_Error = 4,
};

struct rpc_message_part {
    uint32_t payload_length; ///< The length of the message.
    uint16_t status; ///< status / errors
    uint8_t method;   ///< Method identifier, see enum rpc_message_method
    char payload[0]; ///< The total payload data of the message.
} __attribute__((packed));      // due to correct ordering not necessary but explicit is better

struct rpc_message {
    struct capref cap; ///< Optional cap to exchange, NULL if not set
    struct rpc_message_part msg;
};

struct serial_getchar_reply {
    uint64_t session;    ///< read session
    char data;           ///< char to get
};

#endif
