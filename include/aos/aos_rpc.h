/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _LIB_BARRELFISH_AOS_MESSAGES_H
#define _LIB_BARRELFISH_AOS_MESSAGES_H

#include <aos/aos.h>
#include <aos/aos_rpc_types.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/aos_rpc_ump.h>
#include <fs/fs.h>

// How often a transient error can occur before it's regarded critical.
#define TRANSIENT_ERR_RETRIES (1000)

// how long to sleep thread and give away execution time until resume on transient error
#define TRANSIENT_ERR_SLEEP_US (1000)

enum aos_rpc_type {
    RpcTypeLmp,
    RpcTypeUmp,
};

/* An RPC binding, which may be transported over LMP or UMP. */
struct aos_rpc {
    struct thread_mutex mutex;
    enum aos_rpc_type type;
    union {
        struct aos_rpc_lmp lmp;
        struct aos_rpc_ump ump;
    };

    void *priv_data;
};

/**
 * \brief Call this handler on the receive side for grading
 */
void aos_rpc_handler_print(char* string, uintptr_t* val, struct capref* cap);

/**
 * \brief Initialize an aos_rpc struct.
 */
errval_t aos_rpc_init(struct aos_rpc *rpc, enum aos_rpc_type type);

/**
 * \brief Send a number.
 */
errval_t aos_rpc_send_number(struct aos_rpc *chan, uintptr_t val);

/**
 * \brief Send a string.
 */
errval_t aos_rpc_send_string(struct aos_rpc *chan, const char *string);

/**
 * \brief Request a RAM capability with >= request_bits of size over the given
 * channel.
 */
errval_t aos_rpc_get_ram_cap(struct aos_rpc *chan, size_t bytes,
                             size_t alignment, struct capref *retcap,
                             size_t *ret_bytes);

/**
 * \brief Request a RAM capability with >= request_bits of size over the given
 * channel.
 */
errval_t aos_rpc_get_remote_ram_cap(
        size_t bytes,
        size_t alignment,
        coreid_t coreid,
        struct capref *ret_cap,
        size_t *ret_bytes
);

/**
 * \brief Get one character from the serial port
 *
 * returns AOS_ERR_SERIAL_BUSY if device is blocked for too long by someone else
 */
errval_t aos_rpc_serial_getchar(struct aos_rpc *chan, char *retc);

/**
 * \brief Send one character to the serial port
 */
errval_t aos_rpc_serial_putchar(struct aos_rpc *chan, char c);

/**
 * \brief Send multiple character to the serial port
 */
errval_t aos_rpc_serial_putstr(struct aos_rpc *rpc, char *str, size_t len);

/**
 * \brief Request that the process manager start a new process
 * \arg name the name of the process that needs to be spawned (without a
 *           path prefix)
 * \arg newpid the process id of the newly-spawned process
 */
errval_t aos_rpc_process_spawn(struct aos_rpc *chan, char *name,
                               coreid_t core, domainid_t *newpid);

/**
 * \brief Get name of process with the given PID.
 * \arg pid the process id to lookup
 * \arg name A null-terminated character array with the name of the process
 * that is allocated by the rpc implementation. Freeing is the caller's
 * responsibility.
 */
errval_t aos_rpc_process_get_name(struct aos_rpc *chan, domainid_t pid,
                                  char **name);

/**
 * \brief Get detailed info about a running processes.
 * \arg pid query process with given pid
 */
errval_t aos_rpc_process_get_info(struct aos_rpc *chan, domainid_t pid,
                                  struct aos_rpc_process_info_reply **ret_info);


/**
 * \brief Get PIDs of all running processes.
 * \arg pids An array containing the process ids of all currently active
 * processes. Will be allocated by the rpc implementation. Freeing is the
 * caller's  responsibility.
 * \arg pid_count The number of entries in `pids' if the call was successful
 */
errval_t aos_rpc_process_get_all_pids(struct aos_rpc *chan,
                                      domainid_t **pids, size_t *pid_count);


/**
 * \brief Signalize end of live for domain
 */
errval_t
aos_rpc_process_signalize_exit(struct aos_rpc *rpc);


/**
 * \brief Read block of SDHC at index
 * \arg index Read block at this index
 * \arg buf Where to store data received
 * \arg buf_size Size of buf
 */
errval_t aos_rpc_block_driver_read_block(struct aos_rpc *rpc,
                                         uint32_t index,
                                         void *buf,
                                         size_t buf_size);

/**
 * \brief Write block of SDHC at index
 * \arg index Write block at this index
 * \arg buf Data to be written
 * \arg block_size Size of block to be written, buf must be at least of this size
 */
errval_t aos_rpc_block_driver_write_block(struct aos_rpc *rpc,
                                          uint32_t index,
                                          void *buf,
                                          size_t block_size);

errval_t aos_rpc_fs_opendir(struct aos_rpc *rpc, const char *path, lvaddr_t *handler);
errval_t aos_rpc_fs_open(struct aos_rpc *rpc, const char *name, lvaddr_t *handler);
errval_t aos_rpc_fs_create(struct aos_rpc *rpc, const char *name, lvaddr_t *handler);
errval_t aos_rpc_fs_rm(struct aos_rpc *rpc, const char *path);
errval_t aos_rpc_fs_rmdir(struct aos_rpc *rpc, const char *path);
errval_t aos_rpc_fs_mkdir(struct aos_rpc *rpc, const char *path);
errval_t aos_rpc_fs_closedir(struct aos_rpc *rpc, lvaddr_t handler);
errval_t aos_rpc_fs_close(struct aos_rpc *rpc, lvaddr_t handler);
errval_t aos_rpc_fs_tell(struct aos_rpc *rpc, lvaddr_t handler, size_t *ret_pos);
errval_t aos_rpc_fs_stat(struct aos_rpc *rpc, lvaddr_t handler, struct fs_fileinfo *fsinfo);
errval_t aos_rpc_fs_read(struct aos_rpc *rpc, lvaddr_t handler, size_t bytes, char **buf, size_t *ret_bytes);
errval_t aos_rpc_fs_read_dir_next(struct aos_rpc *rpc, lvaddr_t handler, char **name);
errval_t aos_rpc_fs_seek(
    struct aos_rpc *rpc,
    lvaddr_t handler,
    off_t offset,
    enum fs_seekpos whence
);
errval_t aos_rpc_fs_write(
    struct aos_rpc *rpc,
    lvaddr_t handler,
    char *buf,
    size_t size,
    size_t *written
);


/**
 * \brief Request a device cap for the given region.
 * @param chan  the rpc channel
 * @param paddr physical address of the device
 * @param bytes number of bytes of the device memory
 * @param frame returned frame
 */
errval_t aos_rpc_get_device_cap(struct aos_rpc *chan,
                                lpaddr_t paddr, size_t bytes,
                                struct capref *frame);

// Nameserver calls
errval_t aos_rpc_ns_register(struct aos_rpc *rpc, const char *name, struct aos_rpc *chan_add_client, domainid_t pid);
errval_t aos_rpc_ns_deregister(struct aos_rpc *rpc, const char *name);
errval_t aos_rpc_ns_lookup(struct aos_rpc *rpc, const char *name, struct aos_rpc *rpc_service, domainid_t *pid);
errval_t aos_rpc_ns_enumerate(struct aos_rpc *rpc, const char *query, size_t *num, char **result);

/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void);

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void);

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void);

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void);

/**
 * \brief Returns the channel to the block driver
 */
struct aos_rpc *aos_rpc_get_block_driver_channel(void);

/**
 * \brief Returns the channel to the file system server
 */
struct aos_rpc *aos_rpc_get_filesystemserver_channel(void);

#endif // _LIB_BARRELFISH_AOS_MESSAGES_H
