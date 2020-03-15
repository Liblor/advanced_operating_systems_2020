#ifndef BF_AOS_PAGING_REGIONS_H
#define BF_AOS_PAGING_REGIONS_H

#include <aos/debug.h>


errval_t add_region(struct paging_state *st, lvaddr_t base, size_t size);
errval_t alloc_region(struct paging_state *st, lvaddr_t addr, size_t size, struct region *ret);
errval_t free_region(struct paging_state *st, struct paging_region *region);
errval_t find_region(struct paging_state *st, void **buf, size_t bytes, size_t alignment);


#endif //BF_AOS_PAGING_REGIONS_H
