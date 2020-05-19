#ifndef BFOS_AOSH_BUILTIN_H
#define BFOS_AOSH_BUILTIN_H

enum aosh_builtin_op {
    Aosh_Builtin_Invalid,
    Aosh_Builtin_Help,
    Aosh_Builtin_Clear,
    Aosh_Builtin_Exit
};

typedef errval_t (*builtin_func_t) (int argc, char **argv);

struct aosh_builtin_descr {
    builtin_func_t fn;
    char *name;
    enum aosh_builtin_op op;
    char *help;
};

errval_t aosh_dispatch_builtin(int argc, char **argv);

#endif //BFOS_AOSH_BUILTIN_H
