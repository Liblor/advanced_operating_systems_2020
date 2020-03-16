/**
 * \file
 * \brief Paging region manager
 */

#include <aos/aos.h>
#include <aos/paging_regions.h>
#include <aos/paging_types.h>
#include <aos/debug.h>


static inline errval_t create_new_region(struct paging_state *st,
                                         struct paging_region **new_region,
                                         lvaddr_t base,
                                         size_t size,
                                         enum nodetype type) {
    void *block = malloc(sizeof(struct paging_region));
    if (block == NULL) { return LIB_ERR_SLAB_ALLOC_FAIL; }

    *new_region = (struct paging_region *)block;
    (*new_region)->type = type;
    (*new_region)->base_addr = base;
    (*new_region)->region_size = size;
    return SYS_ERR_OK;
}

static inline void insert_before(struct paging_state *st, struct paging_region *new_region, struct paging_region *before) {
    new_region->prev = before->prev;
    if (new_region->prev != NULL) {
        new_region->prev->next = new_region;
    } else {
        assert(st->head == before);
        st->head = new_region;
    }
    new_region->next = before;
    before->prev = new_region;
}

/**
 * Removes region node from linked list. Does NOT free the memory of node
 * @param st
 * @param region Region to remove
 */
static void remove_node(struct paging_state *st, struct paging_region *region) {
    if (region->prev != NULL) {
        region->prev->next = region->next;
    } else {
        assert(st->head == region);
        st->head = region->next;
    }
    if (region->next != NULL) {
        region->next->prev = region->prev;
    } else {
        assert(st->tail == region);
        st->tail = region->prev;
    }
    region->prev = region->next = NULL;
}


static inline void merge_with_prev_node(struct paging_state *st, struct paging_region *region) {
    assert(region->type == region->prev->type);
    assert(region->prev->base_addr + region->prev->region_size == region->base_addr);
    if (st->head == region->prev) {
        st->head = region;
    }
    region->base_addr = region->prev->base_addr;
    region->current_addr = region->base_addr;
    region->region_size += region->prev->region_size;

    struct paging_region *to_delete = region->prev;
    remove_node(st, to_delete);
    free(to_delete);
}

static inline errval_t split_off(struct paging_state *st, struct paging_region *region, size_t size) {
    // create new node
    struct paging_region *new_region;
    errval_t err = create_new_region(st, &new_region, region->base_addr, size, NodeType_Free);
    if (err_is_fail(err)) { return err; }

    // Update node
    region->base_addr += size;
    region->region_size -= size;

    insert_before(st, new_region, region);

    return SYS_ERR_OK;
}

static inline bool is_in_free_region(struct paging_region *region, lvaddr_t addr, size_t size) {
    bool addr_start = region->base_addr <= addr;
    bool no_overflow = addr + size > addr;
    bool end = addr + size <= region->base_addr + region->region_size;
    bool is_free = region->type == NodeType_Free;
    return addr_start && no_overflow && end && is_free;
}

static inline bool is_mergeable(struct paging_region *prev, struct paging_region *next) {
    return prev != NULL && prev->next == next && prev->type == next->type;
}

static inline bool is_region_free(struct paging_region *region, gensize_t size, gensize_t alignment) {
    genpaddr_t aligned_base = ROUND_UP(region->base_addr, alignment);
    bool no_overflow = aligned_base >= region->base_addr;
    bool in_range = region->base_addr + region->region_size > aligned_base;
    bool enough_space = region->region_size - (aligned_base - region->base_addr) >= size;

    return region->type == NodeType_Free && no_overflow && in_range && enough_space;
}

//////////////////////////////////////////////////////////////////////////////


errval_t add_region(struct paging_state *st, lvaddr_t base, size_t size) {
    struct paging_region *region;
    errval_t err = create_new_region(st, &region, base, size, NodeType_Free);
    if (err_is_fail(err)) { return err; }

    // append node
    if (st->head == NULL) {
        assert(st->tail == NULL);
        st->head = st->tail = region;
    } else {
        assert(st->tail != NULL);
        st->tail->next = region;
       region->prev = st->tail;
        st->tail = region;
    }

    return SYS_ERR_OK;
}

errval_t alloc_region(struct paging_state *st, lvaddr_t addr, size_t size, struct paging_region *ret) {
    errval_t err;
    ret = NULL;
    struct paging_region *curr = st->head;
    while (curr != NULL && is_in_free_region(curr, addr, size)) { curr = curr->next; }
    if (curr == NULL) { return LIB_ERR_OUT_OF_VIRTUAL_ADDR; }

    if (addr == curr->base_addr) {
        err = split_off(st, curr, size);
        if (err_is_fail(err)) { return err; }
    } else {
        // TODO: remove size 0 nodes if it isn't end of original ram cap
        gensize_t pad_size = (addr - curr->base_addr);
        err = split_off(st, curr, pad_size);
        if (err_is_fail(err)) { return err; }
        err = split_off(st, curr, size);
        if (err_is_fail(err)) { return err; }
    }
    ret = curr->prev;
    ret->type = NodeType_Allocated;

    return SYS_ERR_OK;
}


errval_t free_region(struct paging_state *st, struct paging_region *region) {
    region->type = NodeType_Free;
    region->current_addr = region->base_addr;

    if (is_mergeable(region->prev, region)) {
        merge_with_prev_node(st, region);
    }
    if (is_mergeable(region, region->next)) {
        merge_with_prev_node(st, region->next);
    }

    return SYS_ERR_OK;
}

errval_t find_region(struct paging_state *st, void **buf, size_t bytes, size_t alignment) {
    *buf = NULL;
    // TODO: should not page aligned vaddr be possible?
    if ((alignment % BASE_PAGE_SIZE) || alignment == 0) { return AOS_ERR_INVALID_ALIGNMENT; }
    bytes = ROUND_UP(bytes, BASE_PAGE_SIZE);

    // find node with enough memory
    struct paging_region *curr = st->head;
    while (curr != NULL && !is_region_free(curr, bytes, alignment)) { curr = curr->next; }
    if (curr == NULL) { return LIB_ERR_OUT_OF_VIRTUAL_ADDR; }

    *buf = (void *) ROUND_UP(curr->base_addr, alignment);       // overflow checked in is_allocatable
    return SYS_ERR_OK;
}
