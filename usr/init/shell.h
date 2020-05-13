
// Created by b on 5/9/20.
//

#ifndef BFOS_SHELL_H
#define BFOS_SHELL_H

#include <drivers/lpuart.h>
#include <drivers/gic_dist.h>

#define SHELL_DEBUG_ON
#if defined(SHELL_DEBUG_ON)
#define SHELL_DEBUG(x...) debug_printf("shell:" x)
#else
#define SHELL_DEBUG(x...) ((void)0)
#endif

struct shell_state {
    struct lpuart_s *lpuart3_state;
    struct gic_dist_s *gic_dist_state;
    struct capref irq_dest_cap;
};

errval_t shell_init(void);

#endif //BFOS_SHELL_H
