#include <stdio.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/systime.h>
#include <math.h>

#define SEND_NUMBER_STOP_MEASURE 1
#define SEND_NUMBER_PRINT_OUTPUT 2
#define SEND_NUMBER_PAYLOAD 3

__unused
static void bench_send_number(void)
{
    struct aos_rpc *rpc = aos_rpc_get_init_channel();
    size_t N = 500;
    errval_t err;
    systime_t res[N];

    for (int i = 0; i < N; i++) {
        systime_t t0 = systime_now();
        err = aos_rpc_send_number(rpc, SEND_NUMBER_PAYLOAD);
        assert(err_is_ok(err));
        res[i] = t0;
    }
    aos_rpc_send_number(rpc, SEND_NUMBER_STOP_MEASURE); // magic number
    for (int i = 0; i < N; i++) {
        systime_t t = res[i];
        uint64_t t_ns = systime_to_ns(t);
        err = aos_rpc_send_number(rpc, t_ns);
        assert(err_is_ok(err));
    }

    err = aos_rpc_send_number(rpc, SEND_NUMBER_PRINT_OUTPUT);
    assert(err_is_ok(err));
}

__unused
static void bench_spawn(void)
{
    struct aos_rpc *rpc = aos_rpc_get_process_channel();
    size_t N = 50;
    errval_t err;
    char binary[] = "dummy";
    coreid_t core = 0;
    uint64_t res[N];

    domainid_t pid;
    for (int i = 0; i < N; i++) {
        systime_t t0 = systime_now();
        err = aos_rpc_process_spawn(rpc, binary, core, &pid);
        systime_t t1 = systime_now();
        assert(err_is_ok(err));
        res[i] = systime_to_ns(t1) - systime_to_ns(t0);
    }

    float total = 0;
    uintptr_t min = SIZE_MAX;
    uintptr_t max = 0;
    float mean = 0.0;
    float sd = 0.0;

    for (int i = 0; i < N; i++) {
        uintptr_t diff = res[i];
        total += diff;
        min = MIN(min, diff);
        max = MAX(max, diff);
    }
    mean = total / N;
    for (int i = 0; i < N; i++) {
        uintptr_t diff = res[i];
        sd += pow(diff - mean, 2);
    }
    sd = sqrt(sd / N);

    debug_printf("N:  %zu\n", N);
    debug_printf("min: %zu ns max: %zu ns\n", min, max);
    debug_printf("sd: %f ns\n", sd);
    debug_printf("mean: %f ns \n", mean);
    debug_printf("mean: %f us \n", mean / 1000);
    debug_printf("mean: %f ms \n", mean / 1000 / 1000);
    debug_printf("mean: %f s\n", mean / 1000 / 1000 / 1000);
}

int main(int argc, char *argv[])
{
    debug_printf("starting benchmarks\n");
//    bench_send_number();
    bench_spawn();

    return EXIT_SUCCESS;
}
