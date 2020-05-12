
// Created by b on 5/9/20.
//

#ifndef BFOS_SHELL_H
#define BFOS_SHELL_H

#define SHELL_DEBUG_ON
#if defined(SHELL_DEBUG_ON)
#define SHELL_DEBUG(x...) debug_printf("shell:" x)
#else
#define SHELL_DEBUG(x...) ((void)0)
#endif


errval_t shell_init(void);

#endif //BFOS_SHELL_H
