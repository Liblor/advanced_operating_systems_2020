#ifndef __AOS_PAGING_REGION_H__
#define __AOS_PAGING_REGION_H__

#include <aos/caddr.h>
#include <aos/paging_types.h>
#include <barrelfish_kpi/types.h>
#include <collections/range_tracker.h>

typedef int paging_flags_t;

struct mapping_list {
    struct capref frame; ///< The capability used to back the memory of the mapping.
    size_t count; ///< Number of mappings that are stored in this list.
    size_t total; ///< Number of mappings that can be stored in this list.
    struct capref *caps; ///< Array of mappings within this region.
};

struct paging_region {
    paging_flags_t flags; ///< The flags with which new frames will be mapped.
    struct range_tracker rt; ///< For managing the second layer, i.e., the actual mappings.
    struct rtnode *node; ///< The node in the upper layer range tracker representing this paging region.
    // TODO Should this be a hash table? This gets very large for large regions
    bool implicit; // Whether this paging region was created automatically or via the paging_region API.
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
