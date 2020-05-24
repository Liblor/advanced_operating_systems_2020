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
    Method_Serial_Putstr,
    Method_Process_Get_Name,
    Method_Process_Get_All_Pids,
    Method_Spawn_Process,
    Method_Process_Ping,
    Method_Localtask_Spawn_Process,
    Method_Nameserver_Register,
    Method_Nameserver_Deregister,
    Method_Nameserver_Lookup,
    Method_Nameserver_Enumerate,
    Method_Ump_Add_Client,
    Method_Nameserver_Service_Request,
    Method_Nameserver_Service_Response,
};

#define AOS_RPC_NAMESERVER_MAX_NAME_LENGTH 32

enum rpc_message_status {
    Status_Ok = 0,
    Spawn_Failed = 1,
    Process_Get_Name_Failed = 2,
    Process_Get_All_Pids_Failed = 3,
    Status_Error = 4,
    Serial_Getchar_Occupied = 5,     // serial read occupied. try again
    Serial_Getchar_Nodata = 6
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

#define SERIAL_GETCHAR_SESSION_UNDEF 0

typedef uint64_t serial_session_t;

struct serial_getchar_reply {
    serial_session_t session;    ///< read session
    char data;                  ///< char to get
};

struct serial_getchar_req {
    serial_session_t session;    ///< read session
};

#endif
