#ifndef _RANGE_TRACKER_H_
#define _RANGE_TRACKER_H_

#include <sys/cdefs.h>
#include <errors/errno.h>
#include <aos/types.h>
#include <aos/capabilities.h>
#include <aos/slab.h>


enum range_tracker_nodetype {
    RangeTracker_NodeType_Free,
    RangeTracker_NodeType_Used
};

union range_tracker_shared {
    void *ptr;
    struct capref cap;
};

struct rtnode {
    enum range_tracker_nodetype type;
    uint64_t original_region_base;
    struct rtnode *prev;
    struct rtnode *next;
    uint64_t base;
    uint64_t size;
    union range_tracker_shared shared;
};

struct range_tracker {
    struct slab_allocator slabs;
    struct rtnode *head;
    struct rtnode rt_head;
    struct rtnode rt_tail;
};

errval_t range_tracker_init(struct range_tracker *rt, slab_refill_func_t slab_refill_func);
errval_t range_tracker_add(struct range_tracker *rt, uint64_t base, uint64_t size, union range_tracker_shared shared);
errval_t range_tracker_alloc_aligned(struct range_tracker *rt, uint64_t size, uint64_t alignment, struct rtnode **retnode);
errval_t range_tracker_alloc_fixed(struct range_tracker *rt, uint64_t base, uint64_t size, struct rtnode *retnode);
errval_t range_tracker_free(struct range_tracker *rt, uint64_t base, uint64_t size, union range_tracker_shared *shared);

void range_tracker_print_state(struct range_tracker *rt);
void range_tracker_destroy(struct range_tracker *rt);

#endif
