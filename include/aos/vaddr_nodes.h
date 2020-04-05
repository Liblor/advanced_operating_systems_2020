#ifndef BF_AOS_VADDR_NODES_H
#define BF_AOS_VADDR_NODES_H

#include <aos/debug.h>
#include <aos/paging_types.h>

enum nodetype {
    NodeType_Free,      ///< This node is free
    NodeType_Reserved,  ///< This node is intended to be used in a paging region, but is not yet allocated
    NodeType_Allocated, ///< This node is allocated but not yet mapped into the page table
    NodeType_Mapped,    ///< This node is mapped into the page table
};

struct vaddr_node {
    lvaddr_t base_addr;
    size_t size;
    struct vaddr_node *next;
    struct vaddr_node *prev;
    enum nodetype type;
    struct paging_region *region;
};

errval_t vaddr_nodes_add(struct paging_state *st, lvaddr_t base, size_t size, struct paging_region *paging_region);
errval_t vaddr_nodes_alloc(struct paging_state *st, lvaddr_t addr, size_t size, struct vaddr_node **ret);
errval_t vaddr_nodes_free(struct paging_state *st, struct vaddr_node *node);
errval_t vaddr_nodes_reserve(struct paging_state *st, void **buf, size_t bytes, size_t alignment);
errval_t vaddr_nodes_is_reserved(struct paging_state *st, lvaddr_t vaddr);

#endif //BF_AOS_VADDR_NODES_H
