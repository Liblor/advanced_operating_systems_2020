//
// Created by b on 5/18/20.
//

#ifndef BFOS_AOSH_H
#define BFOS_AOSH_H

#include <aos/aos_rpc.h>

//void aosh_clear_screen(void)

#define AOSH_READLINE_MAX_LEN 1024
#define AOSH_MAX_ARGC 32

struct aosh_state {
    char read_buffer[AOSH_READLINE_MAX_LEN];
};

#endif //BFOS_AOSH_H
