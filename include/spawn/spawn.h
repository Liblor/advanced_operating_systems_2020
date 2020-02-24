/**
 * \file
 * \brief create child process library
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _INIT_SPAWN_H_
#define _INIT_SPAWN_H_

#include "aos/slot_alloc.h"
#include "aos/paging.h"



struct spawninfo {
    // the next in the list of spawned domains
    struct spawninfo *next; 

    // Information about the binary
    char * binary_name;     // Name of the binary

    // TODO(M2): Add fields you need to store state
    //           when spawning a new dispatcher,
    //           e.g. references to the child's
    //           capabilities or paging state

};

// Start a child process using the multiboot command line. Fills in si.
errval_t spawn_load_by_name(char *binary_name, struct spawninfo * si,
                            uint32_t * pid);

// Start a child with an explicit command line. Fills in si.
errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si,
                         domainid_t *pid);




#endif /* _INIT_SPAWN_H_ */
