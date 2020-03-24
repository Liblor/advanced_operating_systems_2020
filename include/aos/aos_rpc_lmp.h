#ifndef _LIB_BARRELFISH_AOS_LMP_H
#define _LIB_BARRELFISH_AOS_LMP_H

#include <aos/aos.h>
#include <aos/aos_rpc.h>

struct rpc_lmp_segment {
    uintptr_t chunk[4]; ///< Bytes that can be sent at a time.
};

/**
 * \brief Call this handler on the receive side for grading
 */
void aos_rpc_lmp_handler_print(char* string, uintptr_t* val, struct capref* cap);

/**
 * \brief Initialize an aos_rpc struct.
 */
errval_t aos_rpc_lmp_init(struct aos_rpc *rpc);

/**
 * \brief Send a number.
 */
errval_t aos_rpc_lmp_send_number(struct aos_rpc *chan, uintptr_t val);

/**
 * \brief Send a string.
 */
errval_t aos_rpc_lmp_send_string(struct aos_rpc *chan, const char *string);

/**
 * \brief Request a RAM capability with >= request_bits of size over the given
 * channel.
 */
errval_t aos_rpc_lmp_get_ram_cap(struct aos_rpc *chan, size_t bytes,
                             size_t alignment, struct capref *retcap,
                             size_t *ret_bytes);

/**
 * \brief Get one character from the serial port
 */
errval_t aos_rpc_lmp_serial_getchar(struct aos_rpc *chan, char *retc);

/**
 * \brief Send one character to the serial port
 */
errval_t aos_rpc_lmp_serial_putchar(struct aos_rpc *chan, char c);

/**
 * \brief Request that the process manager start a new process
 * \arg name the name of the process that needs to be spawned (without a
 *           path prefix)
 * \arg newpid the process id of the newly-spawned process
 */
errval_t aos_rpc_lmp_process_spawn(struct aos_rpc *chan, char *name,
                               coreid_t core, domainid_t *newpid);

/**
 * \brief Get name of process with the given PID.
 * \arg pid the process id to lookup
 * \arg name A null-terminated character array with the name of the process
 * that is allocated by the rpc implementation. Freeing is the caller's
 * responsibility.
 */
errval_t aos_rpc_lmp_process_get_name(struct aos_rpc *chan, domainid_t pid,
                                  char **name);

/**
 * \brief Get PIDs of all running processes.
 * \arg pids An array containing the process ids of all currently active
 * processes. Will be allocated by the rpc implementation. Freeing is the
 * caller's  responsibility.
 * \arg pid_count The number of entries in `pids' if the call was successful
 */
errval_t aos_rpc_lmp_process_get_all_pids(struct aos_rpc *chan,
                                      domainid_t **pids, size_t *pid_count);

/**
 * \brief Request a device cap for the given region.
 * @param chan  the rpc channel
 * @param paddr physical address of the device
 * @param bytes number of bytes of the device memory
 * @param frame returned frame
 */
errval_t aos_rpc_lmp_get_device_cap(struct aos_rpc *chan,
                                lpaddr_t paddr, size_t bytes,
                                struct capref *frame);

/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_lmp_get_init_channel(void);

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_lmp_get_memory_channel(void);

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_lmp_get_process_channel(void);

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_lmp_get_serial_channel(void);

#endif // _LIB_BARRELFISH_AOS_LMP_H