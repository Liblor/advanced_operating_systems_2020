#include <stdio.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>

int main(int argc, char *argv[])
{
    debug_printf("Dummy spawned\n");
    char buf[512];
    errval_t err = aos_rpc_block_driver_read_block(aos_rpc_get_block_driver_channel(), 0, buf, 512);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Block driver rpc fail\n");
    }

    printf("0x%x\n", buf[0]);
    assert(buf[0] == 0xeb);
    //err = aos_rpc_block_driver_write_block(aos_rpc_get_block_driver_channel(), 0, buf, 512);
    //if (err_is_fail(err)) {
        //DEBUG_ERR(err, "Block driver rpc fail\n");
    //}


    return EXIT_SUCCESS;
}
