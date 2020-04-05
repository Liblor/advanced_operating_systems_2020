/**
 * \file
 * \brief Paging nodes manager
 */

#include <aos/aos.h>
#include <aos/paging_types.h>
#include <aos/vaddr_nodes.h>
#include <aos/debug.h>

static inline errval_t create_new_node(
    struct paging_state *st,
    struct vaddr_node **ret_node,
    lvaddr_t base,
    size_t size,
    struct paging_region *paging_region,
    enum nodetype type
)
{
    assert(st != NULL);
    assert(ret_node != NULL);
    assert(st->slabs.blocksize >= sizeof(struct vaddr_node));

    *ret_node = NULL;

    slab_ensure_threshold(&st->slabs, 10);

    struct vaddr_node *node = slab_alloc(&st->slabs);
    if (node == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    memset(node, 0x00, sizeof(struct vaddr_node));

    node->type = type;
    node->base_addr = base;
    node->size = size;
    node->region = paging_region;

    *ret_node = node;

    return SYS_ERR_OK;
}

static inline void insert_before(
    struct paging_state *st,
    struct vaddr_node *new_node,
    struct vaddr_node *before
)
{
    assert(st != NULL);
    assert(new_node != NULL);
    assert(before != NULL);

    new_node->prev = before->prev;

    if (new_node->prev != NULL) {
        new_node->prev->next = new_node;
    } else {
        assert(st->head == before);
        st->head = new_node;
    }

    new_node->next = before;
    before->prev = new_node;
}

/**
 * Removes paging node from linked list. Does NOT free the memory of node
 * @param st
 * @param node Node to remove
 */
static void remove_node(
    struct paging_state *st,
    struct vaddr_node *node
)
{
    assert(st != NULL);
    assert(node != NULL);

    if (node->prev != NULL) {
        node->prev->next = node->next;
    } else {
        assert(st->head == node);
        st->head = node->next;
    }

    if (node->next != NULL) {
        node->next->prev = node->prev;
    } else {
        assert(st->tail == node);
        st->tail = node->prev;
    }

    node->prev = node->next = NULL;
}

static inline void merge_with_prev_node(
    struct paging_state *st,
    struct vaddr_node *node
)
{
    assert(st != NULL);
    assert(node != NULL);
    assert(node->type == node->prev->type);
    assert(node->prev->base_addr + node->prev->size == node->base_addr);

    if (st->head == node->prev) {
        st->head = node;
    }

    node->base_addr = node->prev->base_addr;
    node->size += node->prev->size;

    struct vaddr_node *to_delete = node->prev;
    remove_node(st, to_delete);
    slab_free(&st->slabs, to_delete);
}

static inline errval_t split_off(
    struct paging_state *st,
    struct vaddr_node *node,
    size_t size
)
{
    errval_t err;

    assert(st != NULL);
    assert(node != NULL);

    // create new node
    struct vaddr_node *new_node;

    err = create_new_node(st, &new_node, node->base_addr, size, NULL, NodeType_Free);
    if (err_is_fail(err)) {
        return err;
    }

    // Update node
    node->base_addr += size;
    node->size -= size;

    insert_before(st, new_node, node);

    return SYS_ERR_OK;
}

static inline bool is_not_mapped_node(
    struct vaddr_node *node,
    lvaddr_t addr,
    size_t size
)
{
    assert(node != NULL);

    bool addr_start = node->base_addr <= addr;
    bool no_overflow = addr + size > addr;
    bool end = addr + size <= node->base_addr + node->size;
    bool not_mapped = node->type != NodeType_Allocated;

    return addr_start && no_overflow && end && not_mapped;
}

static inline bool is_reserved_node(
    struct vaddr_node *node,
    lvaddr_t addr,
    size_t size
)
{
    assert(node != NULL);

    bool addr_start = node->base_addr <= addr;
    bool no_overflow = addr + size > addr;
    bool end = addr + size <= node->base_addr + node->size;
    bool reserved = node->type == NodeType_Reserved;

    return addr_start && no_overflow && end && reserved;
}

static inline bool is_mergeable(
    struct vaddr_node *prev,
    struct vaddr_node *next
)
{
    assert(prev != NULL);
    assert(next != NULL);

    return prev != NULL && prev->next == next && prev->type == next->type;
}

static inline bool is_node_free(
    struct vaddr_node *node,
    gensize_t size,
    gensize_t alignment
)
{
    assert(node != NULL);

    genpaddr_t aligned_base = ROUND_UP(node->base_addr, alignment);
    bool no_overflow = aligned_base >= node->base_addr;
    bool in_range = node->base_addr + node->size > aligned_base;
    bool enough_space = node->size - (aligned_base - node->base_addr) >= size;

    return node->type == NodeType_Free && no_overflow && in_range && enough_space;
}

errval_t vaddr_nodes_add(
    struct paging_state *st,
    lvaddr_t base,
    size_t size,
    struct paging_region *paging_region
)
{
    errval_t err;

    assert(st != NULL);

    struct vaddr_node *node;

    err = create_new_node(st, &node, base, size, paging_region, NodeType_Free);
    if (err_is_fail(err)) {
        return err;
    }

    // append node
    if (st->head == NULL) {
        assert(st->tail == NULL);
        st->head = st->tail = node;
    } else {
        assert(st->tail != NULL);
        st->tail->next = node;
       node->prev = st->tail;
        st->tail = node;
    }

    return SYS_ERR_OK;
}

errval_t vaddr_nodes_alloc(
    struct paging_state *st,
    lvaddr_t addr,
    size_t size,
    struct vaddr_node **ret
)
{
    errval_t err;

    assert(st != NULL);

    *ret = NULL;
    struct vaddr_node *curr = st->head;

    while (curr != NULL && !is_not_mapped_node(curr, addr, size)) {
        curr = curr->next;
    }

    if (curr == NULL) {
        return LIB_ERR_OUT_OF_VIRTUAL_ADDR;
    }

    if (addr == curr->base_addr) {
        err = split_off(st, curr, size);
        if (err_is_fail(err)) {
            return err;
        }
    } else {
        // TODO: remove size 0 nodes if it isn't end of original ram cap
        gensize_t pad_size = (addr - curr->base_addr);

        err = split_off(st, curr, pad_size);
        if (err_is_fail(err)) {
            return err;
        }

        err = split_off(st, curr, size);
        if (err_is_fail(err)) {
            return err;
        }
    }

    *ret = curr->prev;
    (*ret)->type = NodeType_Allocated;

    return SYS_ERR_OK;
}

errval_t vaddr_nodes_free(
    struct paging_state *st,
    struct vaddr_node *node
)
{
    assert(st != NULL);
    assert(node != NULL);

    node->type = NodeType_Free;

    if (is_mergeable(node->prev, node)) {
        merge_with_prev_node(st, node);
    }
    if (is_mergeable(node, node->next)) {
        merge_with_prev_node(st, node->next);
    }

    return SYS_ERR_OK;
}

errval_t vaddr_nodes_reserve(
    struct paging_state *st,
    void **buf,
    size_t bytes,
    size_t alignment
)
{
    errval_t err;

    assert(st != NULL);
    assert(buf != NULL);

    *buf = NULL;
    if ((alignment % BASE_PAGE_SIZE) || alignment == 0) {
        return AOS_ERR_INVALID_ALIGNMENT;
    }
    bytes = ROUND_UP(bytes, BASE_PAGE_SIZE);

    // find node with enough memory
    struct vaddr_node *curr = st->head;

    while (curr != NULL && !is_node_free(curr, bytes, alignment)) {
        curr = curr->next;
    }

    if (curr == NULL) {
        return LIB_ERR_OUT_OF_VIRTUAL_ADDR;
    }

    lvaddr_t vaddr = ROUND_UP(curr->base_addr, alignment);   // overflow checked in is_allocatable
    *buf = (void *)vaddr;

    if (vaddr == curr->base_addr) {
        err = split_off(st, curr, bytes);
        if (err_is_fail(err)) {
            return err;
        }
    } else {
        // TODO: remove size 0 nodes if it isn't end of original ram cap
        gensize_t pad_size = (vaddr - curr->base_addr);

        err = split_off(st, curr, pad_size);
        if (err_is_fail(err)) {
            return err;
        }

        err = split_off(st, curr, bytes);
        if (err_is_fail(err)) {
            return err;
        }
    }

    assert(vaddr == curr->prev->base_addr);
    curr->prev->type = NodeType_Reserved;

    // XXX: maybe it makes sense to merge with neighboring nodes if they are also reserved

    return SYS_ERR_OK;
}

/**
 * Checks if the virtual address vaddr is marked as reserved
 */
errval_t vaddr_nodes_is_reserved(
    struct paging_state *st,
    lvaddr_t vaddr
)
{
    assert(st != NULL);

    // XXX: is there a benefit to check over larger sizes
    size_t size = BASE_PAGE_SIZE;
    struct vaddr_node *curr = st->head;

    // XXX: easy optimization, break after vaddr > curr->base_addr
    while (curr != NULL && !is_reserved_node(curr, vaddr, size)) {
        curr = curr->next;
    }

    return (curr != NULL);
}
