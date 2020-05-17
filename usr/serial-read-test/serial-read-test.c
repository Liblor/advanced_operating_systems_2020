#include <stdio.h>

#include <aos/aos.h>
#include <aos/debug.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <aos/string.h>

#include <unistd.h>

__unused
static void clearScreen(void)
{
    printf("\e[1;1H\e[2J");
    fflush(stdout);
}

__unused
static void read_loop(void)
{
    errval_t err;
    struct aos_rpc *rpc = aos_rpc_get_serial_channel();

    const size_t buf_size = 2048;
    char buf[2048];
    memset(&buf, 0, buf_size);

    printf("Write something and hit return\r\n");

    int i = 0;
    do {
        char c;
        err = aos_rpc_lmp_serial_getchar(rpc, &c);
        if (err_is_fail(err)) {
            thread_yield();
            continue;
        }

        if (IS_CHAR_LINEBREAK(c)) {
            // clearScreen();
             printf("\n\rYou typed: '%s' \n\r", &buf);
//            debug_printf("you typed: %s\n", &buf);
//            fflush(stdout);
            memset(&buf,0, 2048);
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
    } while (err_is_ok(err));

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "aos_rpc_lmp_serial_getchar()");
        return;
    }
    debug_printf("\n");
}

__unused
int main(int argc, char *argv[])
{
    printf("Running serial-read test...\n");
    read_loop();

    fflush(stdout);


    return EXIT_SUCCESS;
}
