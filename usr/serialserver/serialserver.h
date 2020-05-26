#ifndef _USR_INIT_SERIALSERVER_H_
#define _USR_INIT_SERIALSERVER_H_

#include <aos/aos_rpc.h>
#include "circular_buf.h"
#include "serial_facade.h"
#include <rpc/server/ump.h>

#define SERIAL_SERVER_DEBUG_ON

#if defined(SERIAL_SERVER_DEBUG_ON)
#define SERIAL_SERVER_DEBUG(x...) debug_printf("serial-server:" x)
#else
#define SERIAL_SERVER_DEBUG(x...) ((void)0)
#endif

#define SERIAL_BUF_SLOTS 128

struct serial_buf_entry {
    char val;
}; __packed

struct session_entry {
    struct serial_buf_entry buf_data[SERIAL_BUF_SLOTS];
    struct cbuf buf;
    serial_session_t session;
    struct session_entry *next;
};

struct serialserver_state {
    struct serial_facade serial_facade;   ///<facade to serial driver in userspace

    size_t read_session_ctr;

    struct session_entry *head;
    struct session_entry *active;
};

#endif
