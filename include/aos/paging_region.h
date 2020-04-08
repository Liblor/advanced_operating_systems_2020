#ifndef __AOS_PAGING_REGION_H__
#define __AOS_PAGING_REGION_H__

#include <aos/caddr.h>
#include <aos/paging_types.h>
#include <barrelfish_kpi/types.h>
#include <collections/range_tracker.h>

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

#endif // __AOS_PAGING_REGION_H__
