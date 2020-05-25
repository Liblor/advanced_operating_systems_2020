#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>
#include <aos/aos_rpc_lmp_marshal.h>
#include <aos/nameserver.h>
#include <aos/deferred.h>
#include <arch/aarch64/aos/dispatcher_arch.h>

#include "builtin.h"
#include "domain_info.h"

errval_t builtin_pid(int argc, char **argv) {
    struct dispatcher_generic *disp = get_dispatcher_generic(curdispatcher());
    domainid_t pid = disp->domain_id;
    printf("%d\n", pid);
    return SYS_ERR_OK;
}

errval_t builtin_coreid(int argc, char **argv) {
    struct dispatcher_generic *disp = get_dispatcher_generic(curdispatcher());
    coreid_t core = disp->core_id;
    printf("%d\n", core);
    return SYS_ERR_OK;
}