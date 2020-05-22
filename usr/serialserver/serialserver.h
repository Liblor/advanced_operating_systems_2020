#ifndef _USR_INIT_SERIALSERVER_H_
#define _USR_INIT_SERIALSERVER_H_

#include <aos/aos_rpc.h>
#include "circular_buf.h"
#include "serial_facade.h"
#include <rpc/server/ump.h>

//#define SERIAL_SERVER_DEBUG_ON

#if defined(SERIAL_SERVER_DEBUG_ON)
#define SERIAL_SERVER_DEBUG(x...) debug_printf("serial-server:" x)
#else
#define SERIAL_SERVER_DEBUG(x...) ((void)0)
#endif

#define SERIAL_BUF_SLOTS 256

struct serial_buf_entry {
    char val;
} __packed;

struct serialserver_state {
    struct rpc_ump_server ump_server;      ///< ump server for rpc calls

    struct serial_facade serial_facade;   ///<facade to serial driver in userspace

    serial_session_t curr_read_session;   ///< read session which got serial_driver
    struct aos_rpc *deferred_rpc;         ///< deferred rpc call because serial driver no input
    size_t read_session_ctr;

    struct cbuf serial_buf;              ///< Ring buffer for arriving serial chars
    struct serial_buf_entry serial_buf_data[SERIAL_BUF_SLOTS]; ///< Ring buffer data
};

#endif
