#ifndef __GRADING_H
#define __GRADING_H

#include <aos/aos.h>

/**
 * Initialises the grading library within the init process on bootstrap core.
 * It will use the address provided in argc/v to consult the bootinfo
 * to determine the arguments to the grading library.
 */
void grading_setup_bsp_init(int argc, char **argv);

/**
 * Initialises the grading library within the init process on application cores.
 * It will use bootinfo pointer to determine the arguments to the grading library.
 *
 * Note: We do not want to restrict your OS design. If you have a design
 * that does not need the bootinfo on the second core, please talk to the
 * assistants. This function is a convenience for the 90% of designs
 * that make the bootinfo available on the second core anyway.
 */
void grading_setup_app_init(struct bootinfo * bi);

/**
 * Initialises the grading library within a generic process. Takes the process's
 * command-line arguments, and removes anything grading-specific. Only
 * use this function in non-init processes. *
 */
void grading_setup_noninit(int *argc, char ***argv);

/**
 * Call this function after initializing your mm implementation.
 * If you have your memory server in a separate process, call me there other
 * wise it should be called in init.
 */
struct mm;
void grading_test_mm(struct mm * mmtest);

/**
 * Call this function to run the tests. In init, call this
 * function after all the library functions are available, but before
 * spwaning any other process.
 */
void grading_test_early(void);

/**
 * Call this function to run the tests. In init, call this
 * function after all the library functions are available, and
 * after all system processes have been created (nameserver and similar).
 */
void grading_test_late(void);
/**
 * Stubs for grading RPC implementation
 * These calls should be called on the receiver side of the RPC defined in
 * lib/aos/aos_rpc.c
 * */
void grading_rpc_handle_number(uintptr_t val);
void grading_rpc_handler_string(const char* string);
void grading_rpc_handler_serial_getchar(void);
void grading_rpc_handler_serial_putchar(char c);
void grading_rpc_handler_ram_cap(size_t bytes, size_t alignment);
void grading_rpc_handler_process_spawn(char* name, coreid_t core);
void grading_rpc_handler_process_get_name(domainid_t pid);
void grading_rpc_handler_process_get_all_pids(void);
void grading_rpc_handler_get_device_cap(lpaddr_t paddr, size_t bytes);

#endif /* __GRADING_H */
