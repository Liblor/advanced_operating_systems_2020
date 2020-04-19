#include <stdarg.h>
#include <stdio.h>

#include <aos/aos.h>
#include <aos/sys_debug.h>
#include <grading.h>

static bool multithreading_test = true;

const char long_string[] = TEST_LONG_STRING;

static void multithreading_rpc_handle_number(uintptr_t val)
{
    static uint64_t sum = 0;
    static uint64_t cnt = 0;

    sum += val;
    cnt++;

    assert(cnt <= TEST_NUM_THREADS * TEST_AOS_RPC_SEND_NUMBER_COUNT);

    if (cnt == TEST_NUM_THREADS * TEST_AOS_RPC_SEND_NUMBER_COUNT) {
        uint64_t expected_sum = 0;
        for (int i = 0; i < TEST_AOS_RPC_SEND_NUMBER_COUNT; i++) {
            expected_sum += i;
        }
        expected_sum *= TEST_NUM_THREADS;

        assert(sum == expected_sum);
        debug_printf("Received all numbers\n");
    }
}

static void multithreading_rpc_handle_string(const char *string)
{
    static uint64_t cnt = 0;

    cnt++;

    assert(cnt <= TEST_NUM_THREADS * TEST_AOS_RPC_SEND_STRING_COUNT);
    assert(strncmp(string, long_string, sizeof(long_string)) == 0);

    if (cnt == TEST_NUM_THREADS * TEST_AOS_RPC_SEND_STRING_COUNT) {
        debug_printf("Received all strings.\n");
    }
}

void grading_rpc_handle_number(uintptr_t val)
{
    if (multithreading_test) {
        multithreading_rpc_handle_number(val);
    }
}

void grading_rpc_handler_string(const char* string)
{
    if (multithreading_test) {
        multithreading_rpc_handle_string(string);
    }
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

void grading_rpc_handler_process_spawn(char* name, coreid_t core)
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
