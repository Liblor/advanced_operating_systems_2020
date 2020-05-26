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
    serial_session_t session;
};

struct session_entry {
    bool is_valid;
    serial_session_t session;
    size_t read_index;
};

struct serialserver_state {
    struct serial_facade serial_facade;   ///<facade to serial driver in userspace

    serial_session_t curr_read_session;   ///< read session which got serial_driver
    size_t read_session_ctr;

    struct cbuf serial_buf;              ///< Ring buffer for arriving serial chars
    struct cbuf session_buf;
    struct serial_buf_entry serial_buf_data[SERIAL_BUF_SLOTS];
    struct session_entry session_data [SERIAL_BUF_SLOTS];
};

#endif
