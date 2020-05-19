#ifndef BFOS_AOSH_BUILTIN_H
#define BFOS_AOSH_BUILTIN_H

#include <aos/aos.h>
#include <aos/string.h>
#include <stdio.h>

typedef errval_t (*builtin_func_t)(int argc, char **argv);

struct aosh_builtin_descr {
    builtin_func_t fn;
    char *name;
    char *help;
};

extern struct aosh_builtin_descr aosh_builtins[];

errval_t aosh_dispatch_builtin(int argc, char **argv);

#endif //BFOS_AOSH_BUILTIN_H
