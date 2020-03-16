#ifndef BF_AOS_PAGING_REGIONS_H
#define BF_AOS_PAGING_REGIONS_H

#include <aos/debug.h>
#include <aos/paging_types.h>

enum nodetype {
    NodeType_Free,      ///< This region exists and is free
    NodeType_Allocated  ///< This region exists and is allocated
};

struct vaddr_region {
    lvaddr_t base_addr;
    size_t size;
    struct vaddr_region *next;
    struct vaddr_region *prev;
    enum nodetype type;
    struct paging_region *region;
};


errval_t add_region(struct paging_state *st, lvaddr_t base, size_t size, struct paging_region *paging_region);
errval_t alloc_vaddr_region(struct paging_state *st, lvaddr_t addr, size_t size, struct vaddr_region **ret);
errval_t free_region(struct paging_state *st, struct vaddr_region *region);
errval_t find_region(struct paging_state *st, void **buf, size_t bytes, size_t alignment);


#endif //BF_AOS_PAGING_REGIONS_H
