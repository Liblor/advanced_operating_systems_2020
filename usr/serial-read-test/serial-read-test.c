#include <stdio.h>

#include <aos/aos.h>
#include <aos/debug.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <aos/string.h>

#include <unistd.h>
#include <aos/systime.h>

__unused
static void clearScreen(void)
{
    printf("\e[1;1H\e[2J");
    fflush(stdout);
}

__unused
static void read_newline(void)
{
    errval_t err;
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();

    const size_t buf_size = 2048;
    char buf[2048];
    memset(&buf, 0, buf_size);
    systime_t id = systime_now();
    printf("[%d] Write something and hit return: ", id);


    int i = 0;

    char c;
    err = aos_rpc_lmp_serial_getchar(rpc, &c);
    if (err != AOS_ERR_SERIAL_BUSY) {
        debug_printf("we timeout because device is busy\n");
        return;
    }
    if (err_is_fail(err)) {
        return;
    }

    if (IS_CHAR_LINEBREAK(c)) {
        // clearScreen();
        printf("\r\n");
        printf("[%d] You typed: '%s'\r\n", id, &buf);
        fflush(stdout);
        memset(&buf, 0, 2048);
        i = 0;
    } else {
        buf[i] = c;
        printf("%c", c);
        fflush(stdout);
        i++;
        if (i == buf_size) {
            i = 0;
        }
    }


    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_serial_getchar()");
        return;
    }
    debug_printf("\n");
}


__unused
static void print_loop(void)
{
    systime_t t = systime_now();
    while (1) {
        // test correct delivery of whole message
        printf("%zu, Im running in a loop\r\n", t);
    }
}


__unused
static void scanf_test(void)
{
    __unused systime_t t = systime_now();
    char c = 0;
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();

    printf("type a key: \r\n");
    errval_t err = aos_rpc_lmp_serial_getchar(rpc, &c);
    printf("you typed: %c\r\n", c);

    if(err_is_fail(err)) {
        DEBUG_ERR(err, "");
    }

}



__unused
int main(int argc, char *argv[])
{
    printf("Running serial-read test...\r\n");

//    read_newline();
//    read_newline();
    scanf_test();


    fflush(stdout);


    return EXIT_SUCCESS;
}
