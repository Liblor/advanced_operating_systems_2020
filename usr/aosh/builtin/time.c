#include "time.h"
#include <aos/sys_debug.h>
#include <aos/systime.h>

static void help(void)
{
    printf("usage: time cmd" ENDL);
    printf("measure time to execute a builtin function" ENDL);
}

static inline cycles_t get_tsc(void)
{
    cycles_t tsc;
    sys_debug_hardware_timer_read((uintptr_t *) &tsc);
    return tsc;
}

errval_t builtin_time(
        int argc,
        char **argv)
{
    if (argc == 1 || *argv[1] == '\0') {
        help();
        return SYS_ERR_OK;
    }
    errval_t err;

    int new_argc = argc - 1;
    char **new_argv = argv + 1;

    uint64_t ticks_before = systime_now();
    cycles_t tsc_before = get_tsc();
    err = aosh_dispatch_builtin(new_argc, new_argv);
    cycles_t tsc_after = get_tsc();
    uint64_t ticks_after = systime_now();
    if (!err_is_ok(err)) {
        printf("command '%s' returned error: %s" ENDL, argv[0], err_getstring(err));
    }
    cycles_t time_ticks = ticks_after - ticks_before;
    cycles_t time_tsc = tsc_after - tsc_before;

    printf(ENDL);
    printf("time results:" ENDL);
    printf("cycles: %zu" ENDL, time_tsc);
    printf("systime ticks: %zu" ENDL, time_ticks);
    printf("systime ns: %zu" ENDL, systime_to_ns(time_ticks));
    printf("systime us: %zu" ENDL, systime_to_us(time_ticks));
    printf("systime ms: %zu" ENDL, systime_to_us(time_ticks) / 1000);
    return SYS_ERR_OK;
}