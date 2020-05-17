#include <stdio.h>

#include <aos/aos.h>
#include <aos/debug.h>
#include <aos/aos_rpc.h>
#include <spawn/spawn.h>
#include <aos/string.h>

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

        if (IS_CHAR_LINEBREAK(c)) {
            buf[i] = 0;
            printf("\r\n");
            printf("You typed: '%s' \r\n", &buf);
            fflush(stdout);
            i = 0;
        } else {
            buf[i] = c;
            fflush(stdout);
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

    printf("done serial-read-test\n");

    return EXIT_SUCCESS;
}
