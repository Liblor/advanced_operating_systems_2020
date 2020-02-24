/**
 * \file
 * \brief Application to test spawning in more depth.
 * 
 * This file contains code to test recursive spawning (a child
 * spawning another child. Note that you need to have implemented
 * aos_rpc_process_spawn for it to work.)
 */

/*
 * Copyright (c) 2020 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#include <stdio.h>
#include <aos/aos.h>
#include <spawn/spawn.h>
#include <aos/aos_rpc.h>

struct aos_rpc *init_rpc;
coreid_t my_core_id;

/**
 * \brief This function accepts a value in the range
 * 0 to 255 and converts it to a string representation.
 * 
 * \param The value to be converted.
 * \return A pointer to a char array that is 4 bytes long
 * and null terminated. Contains the value represented by
 * 3 digits.
 */
static char * utostr(uint8_t i) {
    char * ret = malloc(4);
    
    *(ret + 3) = '\0';
    for (int it = 2; it >= 0; it--) {
        *(ret + it) = '0' + (i % 10);
        i /= 10;
    }
    return ret;
} 

int main(int argc, char *argv[]) {
    
    // get a channel to init
    init_rpc = aos_rpc_get_init_channel();
    if (!init_rpc) {
        DEBUG_PRINTF("init RPC channel NULL?\n");
        return EXIT_FAILURE;
    }
    my_core_id = disp_get_current_core_id();

    if (argc < 2) {
        DEBUG_PRINTF("spawnTester with level 0 is running.\n");
        return EXIT_SUCCESS;

    } else {
        uint8_t level = strtoul(argv[1], NULL, 10);
        DEBUG_PRINTF("spawnTester with level %d is running.\n", level);

        if (level > 0) {
            errval_t err;
            uint32_t spawnTester_pid;
            char cmdline[64];
            sprintf(cmdline, "spawnTester %s", utostr(level - 1));
            // spawn another spawnTester with the level decreased by 1 on the same core
            err = aos_rpc_process_spawn(init_rpc, cmdline, my_core_id, &spawnTester_pid);
            if (err_is_fail(err)) {
                DEBUG_PRINTF("Starting spawnTester failed.\n");
                return EXIT_FAILURE;
            } 
            DEBUG_PRINTF("Starting spawnTester succeded.\n");
        }
        return EXIT_SUCCESS;
    }
}