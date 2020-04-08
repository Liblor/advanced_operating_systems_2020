#ifndef _RANGE_TRACKER_H_
#define _RANGE_TRACKER_H_

#include <aos/caddr.h>
#include <aos/slab.h>
#include <errors/errno.h>
#include <sys/cdefs.h>

struct range_tracker_closure {
    void (*handler)(void *arg);
    void *arg;
};

#define MKRTCLOSURE(h, a) (struct range_tracker_closure) { /*handler*/ (void (*)(void *arg))(h), /*arg*/ (a) }

enum range_tracker_nodetype {
    RangeTracker_NodeType_Free,
    RangeTracker_NodeType_Used
};

union range_tracker_shared {
    void *ptr;
    struct capref cap;
};

typedef void (*range_tracker_free_cb_t)(
    void *callback_state,
    union range_tracker_shared shared,
    uint64_t base,
    uint64_t size
);

struct rtnode {
    enum range_tracker_nodetype type;
    uint64_t original_region_base;
    struct rtnode *prev;
    struct rtnode *next;
    uint64_t base;
    uint64_t size;
    union range_tracker_shared shared;
};

#define RANGE_TRACKER_NODE_SIZE (sizeof(struct rtnode))

struct range_tracker {
    struct slab_allocator *slabs;
    struct rtnode *head;
    struct rtnode rt_head;
    struct rtnode rt_tail;
    uint64_t alignment;
};

errval_t range_tracker_init_aligned(
    struct range_tracker *rt,
    struct slab_allocator *slabs,
    const uint64_t alignment
);

errval_t range_tracker_init(
    struct range_tracker *rt,
    struct slab_allocator *slabs
);

errval_t range_tracker_add(
    struct range_tracker *rt,
    const uint64_t base,
    const uint64_t size,
    union range_tracker_shared shared
);

errval_t range_tracker_alloc_aligned(
    struct range_tracker *rt,
    const uint64_t size,
    const uint64_t alignment,
    struct rtnode **retnode
);

errval_t range_tracker_alloc_fixed(
    struct range_tracker *rt,
    const uint64_t base,
    const uint64_t size,
    struct rtnode **retnode
);

errval_t range_tracker_free(
    struct range_tracker *rt,
    const uint64_t base,
    const uint64_t size,
    struct range_tracker_closure closure
);

errval_t range_tracker_get(
    struct range_tracker *rt,
    const uint64_t size,
    const uint64_t alignment,
    struct rtnode **retnode,
    uint64_t * padding_size
);

errval_t range_tracker_get_fixed(
    struct range_tracker *rt,
    const uint64_t base,
    const uint64_t size,
    struct rtnode **retnode
);

void range_tracker_print_state(
    struct range_tracker *rt
);

void range_tracker_destroy(
    struct range_tracker *rt
);

static inline bool range_tracker_is_used(
    struct rtnode *node
)
{
    return node->type == RangeTracker_NodeType_Used;
}

#endif
