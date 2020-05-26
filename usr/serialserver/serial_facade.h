
// Created by b on 5/9/20.
//

#ifndef BFOS_SERIAL_FACADE_H
#define BFOS_SERIAL_FACADE_H

#include <drivers/lpuart.h>
#include <drivers/gic_dist.h>

// #define SERIAL_FACADE_TRACE_IQR_ON
// enable SERIAL_FACADE_TRACE_IQR_ON
// to write all read iqr directly out through serial port

#define SERIAL_FACADE_DEBUG_ON
#if defined(SERIAL_FACADE_DEBUG_ON)
#define SERIAL_FACADE_DEBUG(x...) debug_printf("serial-facade: " x)
#else
#define SERIAL_FACADE_DEBUG(x...) ((void)0)
#endif

// disable userspace iqr handler for read events
// useful for debugging
// #define SERIAL_FACADE_DISABLE_IQR

typedef void (*serial_facade_read_cb)(char c, void *args);

struct serial_facade {
    bool enable_iqr;
    struct lpuart_s *lpuart3_state;
    struct gic_dist_s *gic_dist_state;
    struct capref irq_dest_cap;
    uint8_t target_cpu;               ///<  8 Bit mask. One bit for each core in the system.
    serial_facade_read_cb read_cb;
    void *read_cb_args;
};

#define SERIAL_FACADE_TARGET_CPU_0 (1)

/**
 * userspace facade for lpuart 3 driver
 *
 * target_cpu is 8 bit mask one bit for each core in system
 */
errval_t serial_facade_init(
        struct serial_facade *state,
        uint8_t target_cpu, bool enable_iqr);

errval_t serial_facade_write(
        struct serial_facade *state,
        char c);

errval_t serial_facade_set_read_cb(
        struct serial_facade *state,
        serial_facade_read_cb cb,
        void *args);

errval_t serial_facade_write_str(
        struct serial_facade *state,
        const char *str,
        size_t len);

errval_t serial_facade_poll_read(
        struct serial_facade *state, char *ret_c);

#endif //BFOS_SERIAL_FACADE_H
