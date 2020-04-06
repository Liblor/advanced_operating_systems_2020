#ifndef BF_AOS_VADDR_NODES_H
#define BF_AOS_VADDR_NODES_H

#include <aos/debug.h>
#include <aos/paging_types.h>

enum nodetype {
    NodeType_Free,      ///< This node is free
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

errval_t vaddr_nodes_alloc_node(
    struct paging_state *st,
    struct vaddr_node *node,
    lvaddr_t base,
    size_t size,
    struct vaddr_node **ret
);

errval_t vaddr_nodes_alloc(struct paging_state *st, lvaddr_t addr, size_t size, struct vaddr_node **ret);

errval_t vaddr_nodes_free(struct paging_state *st, struct vaddr_node *node);

struct vaddr_node *vaddr_nodes_get(
    struct paging_state *st,
    const lvaddr_t base,
    const size_t size
);

struct vaddr_node *vaddr_nodes_get_free(
    struct paging_state *st,
    const size_t size,
    const size_t alignment
);

bool vaddr_nodes_is_type(
    struct vaddr_node *node,
    enum nodetype type
);

errval_t vaddr_nodes_set_region(
    struct paging_state *st,
    struct vaddr_node *node,
    lvaddr_t base,
    size_t size,
    struct paging_region *region
);

#endif //BF_AOS_VADDR_NODES_H
