#ifndef __AOS_PAGING_REGION_H__
#define __AOS_PAGING_REGION_H__

#include <aos/caddr.h>
#include <aos/paging_types.h>
#include <barrelfish_kpi/types.h>
#include <collections/range_tracker.h>

#define PAGING_REGION_LOCK thread_mutex_lock_nested(pr->mutex)
#define PAGING_REGION_UNLOCK thread_mutex_unlock(pr->mutex)

errval_t paging_region_init(
    struct paging_state *st,
    struct paging_region *pr,
    size_t size,
    paging_flags_t flags
);

errval_t paging_region_init_fixed(
    struct paging_state *st,
    struct paging_region *pr,
    lvaddr_t base,
    size_t size,
    paging_flags_t flags
);

errval_t paging_region_init_aligned(
    struct paging_state *st,
    struct paging_region *pr,
    size_t size,
    size_t alignment,
    paging_flags_t flags
);

errval_t paging_region_map(
    struct paging_region *pr,
    size_t req_size,
    void **retbuf,
    size_t *ret_size
);

errval_t paging_region_unmap(
    struct paging_region *pr,
    lvaddr_t base,
    size_t bytes
);

errval_t paging_region_unmap_all(
    struct paging_region *pr
);

#endif // __AOS_PAGING_REGION_H__
