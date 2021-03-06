//
// Created by b on 5/18/20.
//

#ifndef BFOS_AOSH_H
#define BFOS_AOSH_H

#include <aos/aos_rpc.h>

//#define AOSH_TRACE_ON
#if defined(AOSH_TRACE_ON)
#define AOSH_TRACE(x...) debug_printf("aosh-trace: " x)
#else
#define AOSH_TRACE(x...) ((void)0)
#endif

#define AOSH_READLINE_MAX_LEN (512)

#define AOSH_CLI_HEAD (COLOR_RED "AOSH " COLOR_BLU ">>> " COLOR_RESET)
void aosh_greet(void);

struct aosh_state {
};

#endif //BFOS_AOSH_H
