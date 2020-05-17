
// Created by b on 5/9/20.
//

#ifndef BFOS_SERIAL_DRIVER_H
#define BFOS_SERIAL_DRIVER_H

#include <drivers/lpuart.h>
#include <drivers/gic_dist.h>

#define SERIAL_DRIVER_DEBUG_ON
#if defined(SERIAL_DRIVER_DEBUG_ON)
#define SERIAL_DEBUG(x...) debug_printf("serial: " x)
#else
#define SERIAL_DEBUG(x...) ((void)0)
#endif

// disable userspace iqr handler for read events
// useful for debugging
// #define SERIAL_DEBUG_DISABLE_IQR

typedef void (* serial_driver_read_cb)(char c);

struct serial_driver_state {
    struct lpuart_s *lpuart3_state;
    struct gic_dist_s *gic_dist_state;
    struct capref irq_dest_cap;
    serial_driver_read_cb read_cb;
};

errval_t serial_driver_init(void);

errval_t serial_driver_write(char c);

errval_t serial_driver_set_read_cb(serial_driver_read_cb cb);

 errval_t serial_driver_write_str(char *str, size_t len);

#endif //BFOS_SERIAL_DRIVER_H
