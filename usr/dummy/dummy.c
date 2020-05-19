#include <stdio.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/fat32.h>

int main(int argc, char *argv[])
{
    debug_printf("Dummy spawned\n");

    struct fat32_mnt *mnt;
    errval_t err = mount_fat32("test", &mnt);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "mount failed\n");
    }

    return EXIT_SUCCESS;
}
