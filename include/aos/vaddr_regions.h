#ifndef BF_AOS_PAGING_REGIONS_H
#define BF_AOS_PAGING_REGIONS_H

#include <aos/debug.h>
#include <aos/paging_types.h>

enum nodetype {
    NodeType_Free,      ///< This region is free
    NodeType_Reserved,  ///< This region is intended to be used in a paging region, but is not yet allocated
    NodeType_Allocated, ///< This region is allocated but not yet mapped into the page table
    NodeType_Mapped,    ///< This region is mapped into the page table
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
errval_t reserve_vaddr_region(struct paging_state *st, void **buf, size_t bytes, size_t alignment);
errval_t is_vaddr_page_reserved(struct paging_state *st, lvaddr_t vaddr);

#endif //BF_AOS_PAGING_REGIONS_H
