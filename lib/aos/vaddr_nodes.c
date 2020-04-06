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
    struct paging_region *region,
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
    node->region = region;

    *ret_node = node;

    return SYS_ERR_OK;
}

// Results in [a-prev] <--> [a] <--> [b] <--> [a->next].
static inline void insert_b_after_a(
    struct paging_state *st,
    struct vaddr_node *a,
    struct vaddr_node *b
)
{
    assert(st != NULL);
    assert(a != NULL);
    assert(b != NULL);

    b->next = a->next;

    if (a->next != NULL) {
        a->next->prev = b;
    } else {
        assert(a == st->tail);
        st->tail = b;
    }

    a->next = b;
    b->prev = a;
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

static inline errval_t split_in_two(
    struct paging_state *st,
    struct vaddr_node *node,
    size_t size,
    struct vaddr_node **ret
)
{
    errval_t err;

    assert(st != NULL);
    assert(node != NULL);

    if (ret != NULL) {
        *ret = NULL;
    }

    struct vaddr_node *new_node;

    err = create_new_node(st, &new_node, node->base_addr + size, node->size - size, node->region, node->type);
    if (err_is_fail(err)) {
        return err;
    }

    insert_b_after_a(st, node, new_node);

    if (ret != NULL) {
        *ret = new_node;
    }

    return SYS_ERR_OK;
}

static inline errval_t split(
    struct paging_state *st,
    struct vaddr_node *node,
    lvaddr_t base,
    size_t size,
    struct vaddr_node **ret
)
{
    errval_t err;

    assert(st != NULL);
    assert(node != NULL);
    assert(ret != NULL);

    // TODO: Return error on violating constraints.
    assert(node->base_addr <= base);
    assert(node->base_addr + node->size >= base);
    assert(node->base_addr + node->size >= base + size);

    // TODO: Return error on overflow.
    assert(node->base_addr + node->size >= node->base_addr);
    assert(base + size >= base);

    *ret = NULL;

    const size_t padding_size = base - node->base_addr;

    struct vaddr_node *leftover = NULL;

    // Create a leftover block if needed.
    if (padding_size + size < node->size) {
        err = split_in_two(st, node, padding_size + size, &leftover);
        if (err_is_fail(err)) {
            return err;
        }

        assert(node->next == leftover);
        assert(leftover->prev == node);
        assert(node->base_addr < leftover->base_addr);
    }

    struct vaddr_node *new_node = node;

    // Create a padding block if needed.
    if (padding_size > 0) {
        err = split_in_two(st, node, padding_size, &new_node);
        if (err_is_fail(err)) {
            return err;
        }

        assert(node->next == new_node);
        assert(new_node->prev == node);
        assert(node->base_addr < new_node->base_addr);
    }

    *ret = new_node;

    return SYS_ERR_OK;
}

static inline bool address_in_node(
    struct vaddr_node *node,
    const lvaddr_t base,
    const size_t size
)
{
    assert(node != NULL);

    bool addr_start = node->base_addr <= base;
    bool no_overflow = base + size > base;
    bool end = base + size <= node->base_addr + node->size;

    return addr_start && no_overflow && end;
}

static inline bool node_has_aligned_capacity(
    struct vaddr_node *node,
    gensize_t size,
    gensize_t alignment
)
{
    assert(node != NULL);
    assert(alignment != 0);

    const genpaddr_t aligned_base = ROUND_UP(node->base_addr, alignment);
    const bool no_overflow = aligned_base >= node->base_addr;
    const bool in_range = node->base_addr + node->size >= aligned_base;
    const bool enough_space = node->base_addr + node->size >= aligned_base + size;

    return no_overflow && in_range && enough_space;
}

struct vaddr_node *vaddr_nodes_get(
    struct paging_state *st,
    const lvaddr_t base,
    const size_t size
)
{
    assert(st != NULL);

    struct vaddr_node *node = st->head;

    // TODO: Break after base > curr->base_addr
    while (node != NULL && !address_in_node(node, base, size)) {
        node = node->next;
    }

    return node;
}

struct vaddr_node *vaddr_nodes_get_free(
    struct paging_state *st,
    const size_t size,
    const size_t alignment
)
{
    assert(st != NULL);

    if ((alignment % BASE_PAGE_SIZE != 0) || alignment == 0) {
        return NULL;
    }

    const size_t new_size = ROUND_UP(size, BASE_PAGE_SIZE);

    // Check for overflow.
    if (new_size < size) {
        return NULL;
    }

    struct vaddr_node *node = st->head;

    while (node != NULL &&
           !(vaddr_nodes_is_type(node, NodeType_Free) && node_has_aligned_capacity(node, new_size, alignment) && node->region == NULL)) {
        node = node->next;
    }

    return node;
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

errval_t vaddr_nodes_add(
    struct paging_state *st,
    lvaddr_t base,
    size_t size,
    struct paging_region *region
)
{
    errval_t err;

    assert(st != NULL);

    struct vaddr_node *node;

    err = create_new_node(st, &node, base, size, region, NodeType_Free);
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

errval_t vaddr_nodes_alloc_node(
    struct paging_state *st,
    struct vaddr_node *node,
    lvaddr_t base,
    size_t size,
    struct vaddr_node **ret
)
{
    errval_t err;

    assert(st != NULL);

    if (ret != NULL) {
        *ret = NULL;
    }

    struct vaddr_node *new_node;

    err = split(st, node, base, size, &new_node);
    if (err_is_fail(err)) {
        debug_printf("split() failed\n");
        return err;
    }

    new_node->type = NodeType_Allocated;

    if (ret != NULL) {
        *ret = new_node;
    }

    return SYS_ERR_OK;
}

errval_t vaddr_nodes_alloc(
    struct paging_state *st,
    lvaddr_t base,
    size_t size,
    struct vaddr_node **ret
)
{
    errval_t err;

    assert(st != NULL);
    assert(ret != NULL);

    *ret = NULL;

    struct vaddr_node *node = vaddr_nodes_get(st, base, size);

    if (node == NULL || !vaddr_nodes_is_type(node, NodeType_Free)) {
        return LIB_ERR_OUT_OF_VIRTUAL_ADDR; // TODO: Is this errval_t correct?
    }

    err = vaddr_nodes_alloc_node(st, node, base, size, ret);
    if (err_is_fail(err)) {
        debug_printf("vaddr_nodes_alloc_node() failed");
        return err;
    }

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

bool vaddr_nodes_is_type(
    struct vaddr_node *node,
    enum nodetype type
)
{
    assert(node != NULL);

    return node->type == type;
}

errval_t vaddr_nodes_set_region(
    struct paging_state *st,
    struct vaddr_node *node,
    lvaddr_t base,
    size_t size,
    struct paging_region *region
)
{
    errval_t err;

    assert(st != NULL);
    assert(node != NULL);

    // These state transitions do not make a lot of sense.
    assert(!(region == NULL && node->region == NULL));
    assert(!(region != NULL && node->region != NULL));

    struct vaddr_node *new_node = node;

    err = split(st, node, base, size, &new_node);
    if (err_is_fail(err)) {
        debug_printf("split() failed\n");
        return err;
    }

    new_node->region = region;

    return SYS_ERR_OK;
}
