/**
 * \file
 * \brief Paging region manager
 */

#include <aos/aos.h>
#include <aos/paging_types.h>
#include <aos/vaddr_regions.h>
#include <aos/debug.h>

static inline errval_t create_new_region(
    struct paging_state *st,
    struct vaddr_region **ret_region,
    lvaddr_t base,
    size_t size,
    struct paging_region *paging_region,
    enum nodetype type
)
{
    assert(st != NULL);
    assert(ret_region != NULL);
    assert(st->slabs.blocksize >= sizeof(struct vaddr_region));

    *ret_region = NULL;

    slab_ensure_threshold(&st->slabs, 10);

    struct vaddr_region *region = slab_alloc(&st->slabs);
    if (region == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    memset(region, 0x00, sizeof(struct vaddr_region));

    region->type = type;
    region->base_addr = base;
    region->size = size;
    region->region = paging_region;

    *ret_region = region;

    return SYS_ERR_OK;
}

static inline void insert_before(
    struct paging_state *st,
    struct vaddr_region *new_region,
    struct vaddr_region *before
)
{
    assert(st != NULL);
    assert(new_region != NULL);
    assert(before != NULL);

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
static void remove_node(
    struct paging_state *st,
    struct vaddr_region *region
)
{
    assert(st != NULL);
    assert(region != NULL);

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

static inline void merge_with_prev_node(
    struct paging_state *st,
    struct vaddr_region *region
)
{
    assert(st != NULL);
    assert(region != NULL);
    assert(region->type == region->prev->type);
    assert(region->prev->base_addr + region->prev->size == region->base_addr);

    if (st->head == region->prev) {
        st->head = region;
    }

    region->base_addr = region->prev->base_addr;
    region->size += region->prev->size;

    struct vaddr_region *to_delete = region->prev;
    remove_node(st, to_delete);
    slab_free(&st->slabs, to_delete);
}

static inline errval_t split_off(
    struct paging_state *st,
    struct vaddr_region *region,
    size_t size
)
{
    errval_t err;

    assert(st != NULL);
    assert(region != NULL);

    // create new node
    struct vaddr_region *new_region;

    err = create_new_region(st, &new_region, region->base_addr, size, NULL, NodeType_Free);
    if (err_is_fail(err)) {
        return err;
    }

    // Update node
    region->base_addr += size;
    region->size -= size;

    insert_before(st, new_region, region);

    return SYS_ERR_OK;
}

static inline bool is_not_mapped_region(
    struct vaddr_region *region,
    lvaddr_t addr,
    size_t size
)
{
    assert(region != NULL);

    bool addr_start = region->base_addr <= addr;
    bool no_overflow = addr + size > addr;
    bool end = addr + size <= region->base_addr + region->size;
    bool not_mapped = region->type != NodeType_Allocated;

    return addr_start && no_overflow && end && not_mapped;
}

static inline bool is_reserved_region(
    struct vaddr_region *region,
    lvaddr_t addr,
    size_t size
)
{
    assert(region != NULL);

    bool addr_start = region->base_addr <= addr;
    bool no_overflow = addr + size > addr;
    bool end = addr + size <= region->base_addr + region->size;
    bool reserved = region->type == NodeType_Reserved;

    return addr_start && no_overflow && end && reserved;
}

static inline bool is_mergeable(
    struct vaddr_region *prev,
    struct vaddr_region *next
)
{
    assert(prev != NULL);
    assert(next != NULL);

    return prev != NULL && prev->next == next && prev->type == next->type;
}

static inline bool is_region_free(
    struct vaddr_region *region,
    gensize_t size,
    gensize_t alignment
)
{
    assert(region != NULL);

    genpaddr_t aligned_base = ROUND_UP(region->base_addr, alignment);
    bool no_overflow = aligned_base >= region->base_addr;
    bool in_range = region->base_addr + region->size > aligned_base;
    bool enough_space = region->size - (aligned_base - region->base_addr) >= size;

    return region->type == NodeType_Free && no_overflow && in_range && enough_space;
}

errval_t add_region(
    struct paging_state *st,
    lvaddr_t base,
    size_t size,
    struct paging_region *paging_region
)
{
    errval_t err;

    assert(st != NULL);

    struct vaddr_region *region;

    err = create_new_region(st, &region, base, size, paging_region, NodeType_Free);
    if (err_is_fail(err)) {
        return err;
    }

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

errval_t alloc_vaddr_region(
    struct paging_state *st,
    lvaddr_t addr,
    size_t size,
    struct vaddr_region **ret
)
{
    errval_t err;

    assert(st != NULL);

    *ret = NULL;
    struct vaddr_region *curr = st->head;

    while (curr != NULL && !is_not_mapped_region(curr, addr, size)) {
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


errval_t free_region(
    struct paging_state *st,
    struct vaddr_region *region
)
{
    assert(st != NULL);
    assert(region != NULL);

    region->type = NodeType_Free;

    if (is_mergeable(region->prev, region)) {
        merge_with_prev_node(st, region);
    }
    if (is_mergeable(region, region->next)) {
        merge_with_prev_node(st, region->next);
    }

    return SYS_ERR_OK;
}

errval_t reserve_vaddr_region(
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
    struct vaddr_region *curr = st->head;

    while (curr != NULL && !is_region_free(curr, bytes, alignment)) {
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

    // XXX: maybe it makes sense to merge with neighboring regions if they are also reserved

    return SYS_ERR_OK;
}

/**
 * Checks if the virtual address vaddr is marked as reserved
 */
errval_t is_vaddr_page_reserved(
    struct paging_state *st,
    lvaddr_t vaddr
)
{
    assert(st != NULL);

    // XXX: is there a benefit to check over larger sizes
    size_t size = BASE_PAGE_SIZE;
    struct vaddr_region *curr = st->head;

    // XXX: easy optimization, break after vaddr > curr->base_addr
    while (curr != NULL && !is_reserved_region(curr, vaddr, size)) {
        curr = curr->next;
    }

    return (curr != NULL);
}
