#include <stdarg.h>
#include <stdio.h>

#include <aos/aos.h>
#include <aos/sys_debug.h>
#include <grading.h>
#include <aos/systime.h>
#include <math.h>
#include <stdio.h>

#define SEND_NUMBER_STOP_MEASURE 1
#define SEND_NUMBER_PRINT_OUTPUT 2
#define SEND_NUMBER_PAYLOAD 3

static collections_listnode *bench_rpc_handle_number_receive;
static collections_listnode *bench_rpc_handle_number_diff;

static bool grading_rpc_handle_number_init = false;
static bool grading_rpc_handle_number_done = false;
static size_t grading_rpc_handle_number_i = 0;

void grading_rpc_handle_number(uintptr_t val)
{
    systime_t t0 = systime_now();
//    debug_printf("%zu\n", t0);
    if (!grading_rpc_handle_number_init) {
        grading_rpc_handle_number_init = true;
        collections_list_create(&bench_rpc_handle_number_diff, free);
        collections_list_create(&bench_rpc_handle_number_receive, free);
    }
    if (!grading_rpc_handle_number_done) {
        if (val != SEND_NUMBER_STOP_MEASURE) {
            assert(val == SEND_NUMBER_PAYLOAD);
            uintptr_t *n = calloc(1, sizeof(uintptr_t));
            *n = systime_to_ns(t0);
            collections_list_insert_tail(bench_rpc_handle_number_receive, n);
        } else {
            grading_rpc_handle_number_done = true;
        }
    } else {
        if (val != SEND_NUMBER_PRINT_OUTPUT) {
            assert(grading_rpc_handle_number_i <
                   collections_list_size(bench_rpc_handle_number_receive));

            uintptr_t *m = collections_list_get_ith_item(bench_rpc_handle_number_receive,
                                                         grading_rpc_handle_number_i);
            grading_rpc_handle_number_i++;
            assert(val < *m);
            uintptr_t *measure = calloc(1, sizeof(uintptr_t));
            *measure = *m - val;
            collections_list_insert_tail(bench_rpc_handle_number_diff, measure);
        } else {

            size_t N = collections_list_size(bench_rpc_handle_number_diff);
            assert(grading_rpc_handle_number_i == N);
            assert(collections_list_size(bench_rpc_handle_number_diff) ==
                   collections_list_size(bench_rpc_handle_number_receive));

            float total = 0;
            uintptr_t min = SIZE_MAX;
            uintptr_t max = 0;
            float mean = 0.0;
            float sd = 0.0;

            for (int i = 0; i < N; i++) {
                uintptr_t *t = collections_list_get_ith_item(bench_rpc_handle_number_diff, i);
                total += *t;
                min = MIN(min, *t);
                max = MAX(max, *t);
            }
            mean = total / N;
            for (int i = 0; i < N; i++) {
                uintptr_t *d = collections_list_get_ith_item(bench_rpc_handle_number_diff, i);
                sd += pow(*d - mean, 2);
            }
            sd = sqrt(sd / N);

            debug_printf("N:  %zu\n", N);
            debug_printf("min: %zu ns max: %zu ns\n", min, max);
            debug_printf("sd: %f ns\n", sd);
            debug_printf("mean: %f ns \n", mean);
            debug_printf("mean: %f us \n", mean / 1000);
            debug_printf("mean: %f ms \n", mean / 1000 / 1000);
            debug_printf("mean: %f s\n", mean / 1000 / 1000 / 1000);

            collections_list_release(bench_rpc_handle_number_diff);
            collections_list_release(bench_rpc_handle_number_receive);
            bench_rpc_handle_number_diff = NULL;
            bench_rpc_handle_number_receive = NULL;
        }
    }
}

void grading_rpc_handler_string(const char* string) {

}

void grading_rpc_handler_serial_getchar(void)
{

}

void grading_rpc_handler_serial_putchar(char c)
{

}

void grading_rpc_handler_ram_cap(size_t bytes, size_t alignment)
{

}

void grading_rpc_handler_process_spawn(char *name, coreid_t core)
{

}

void grading_rpc_handler_process_get_name(domainid_t pid)
{

}

void grading_rpc_handler_process_get_all_pids(void)
{

}

void grading_rpc_handler_get_device_cap(lpaddr_t paddr, size_t bytes)
{

}
