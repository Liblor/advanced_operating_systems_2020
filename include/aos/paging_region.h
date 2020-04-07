#ifndef __AOS_PAGING_REGION_H__
#define __AOS_PAGING_REGION_H__

#include <aos/aos.h>

typedef int paging_flags_t;

struct paging_region {
    paging_flags_t flags; ///< The flags with which new frames will be mapped.
    struct range_tracker rt; ///< For managing the second layer, i.e., the actual mappings.
    // TODO Should this be a hash table? This gets very large for large regions
    size_t mapping_count; ///< Number of mappings.
    struct capref *mappings; ///< Array of allocated mappings within this region.
    struct capref frame_cap; ///< Frame capability to back the region with physical memory. If it is NULL_CAP it will be necessary to allocate a new frame when a page fault in this region occurs.
};

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
