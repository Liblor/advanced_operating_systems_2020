/**
 * \file
 * \brief Morecore implementation for malloc
 */


/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2011, 2019 ETH Zurich.
 * Copyright (c) 2014, HP Labs.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <aos/aos.h>
#include <aos/core_state.h>
#include <aos/morecore.h>
#include <stdio.h>
#include <aos_malloc.h>

typedef void *(*morecore_alloc_func_t)(size_t bytes, size_t *retbytes);
extern morecore_alloc_func_t sys_morecore_alloc;

typedef void (*morecore_free_func_t)(void *base, size_t bytes);
extern morecore_free_func_t sys_morecore_free;

extern alt_malloc_t alt_malloc;
extern alt_free_t alt_free;
extern alt_free_t alt_free_locked;

// this define makes morecore use an implementation that just has a static
// 16MB heap.
//#define USE_STATIC_HEAP

#ifdef USE_STATIC_HEAP

// dummy mini heap (16M)

#define HEAP_SIZE (1<<24)

static char mymem[HEAP_SIZE] = { 0 };
static char *endp = mymem + HEAP_SIZE;

/**
 * \brief Allocate some memory for malloc to use
 *
 * This function will keep trying with smaller and smaller frames till
 * it finds a set of frames that satisfy the requirement. retbytes can
 * be smaller than bytes if we were able to allocate a smaller memory
 * region than requested for.
 */
static void *morecore_alloc(size_t bytes, size_t *retbytes)
{
    struct morecore_state *state = get_morecore_state();

    size_t aligned_bytes = ROUND_UP(bytes, sizeof(Header));
    void *ret = NULL;
    if (state->freep + aligned_bytes < endp) {
        ret = state->freep;
        state->freep += aligned_bytes;
    }
    else {
        aligned_bytes = 0;
    }
    *retbytes = aligned_bytes;
    return ret;
}

static void morecore_free(void *base, size_t bytes)
{
    return;
}

errval_t morecore_init(size_t alignment)
{
    struct morecore_state *state = get_morecore_state();

    debug_printf("initializing static heap\n");

    //thread_mutex_init(state->mutex);
    state->mutex = &get_current_paging_state()->mutex;

    state->freep = mymem;

    sys_morecore_alloc = morecore_alloc;
    sys_morecore_free = morecore_free;
    return SYS_ERR_OK;
}

errval_t morecore_reinit(void)
{
    return SYS_ERR_OK;
}

// dummy functions, implemented in dynamic heap
void morecore_enable_static(void){}
void morecore_enable_dynamic(void){}

#else

#define HEAP_SIZE (1000 * BASE_PAGE_SIZE)
static char mymem[HEAP_SIZE] = { 0 };
static char *endp = mymem + HEAP_SIZE;


static void morecore_init_static(struct morecore_state *state, size_t alignment)
{
    state->freep = mymem;
    state->header_freep_static = NULL;
    memset(&state->static_zone, 0, sizeof(struct morecore_static_zone));
}

static inline bool static_zone_is_initalized(struct morecore_state *state)
{
    return state->static_zone.region_size != 0;
}

static inline bool static_zone_needs_refill(struct morecore_state *state, size_t requested_bytes)
{
    const bool buf_too_small = state->freep + requested_bytes > endp - MORECORE_FREE_STATIC_THRESHOLD;

    const lvaddr_t new_end = state->static_zone.current_addr + requested_bytes;
    const lvaddr_t curr_end = state->static_zone.base_addr + state->static_zone.backed_size;
    const bool static_zone_too_small = new_end > curr_end - MORECORE_FREE_STATIC_THRESHOLD;
    const bool is_backed = state->static_zone.backed_size != 0;
    return (buf_too_small && (!is_backed || static_zone_too_small));
}

static errval_t initialize_static_zone(struct morecore_state *state)
{
    errval_t err;
    err = paging_alloc(get_current_paging_state(),
            (void **)&state->static_zone.base_addr,
            MORECORE_VADDR_ZONE_SIZE ,
            BASE_PAGE_SIZE);

    if (err_is_fail(err)) {
        debug_printf("initialize_static_zone failed: requesting vaddr space failed\n");
        return err;
    }
    state->static_zone.region_size = MORECORE_VADDR_ZONE_SIZE;
    state->static_zone.current_addr = state->static_zone.base_addr;
    return SYS_ERR_OK;
}


static errval_t ensure_static_threshold(struct morecore_state *state, size_t requested_bytes)
{
    errval_t err = SYS_ERR_OK;
    if (state->static_zone.is_refilling) { return SYS_ERR_OK; }

    state->static_zone.is_refilling = true;
    if (!static_zone_needs_refill(state, requested_bytes)) { goto finish_refill; }

    // We initialize lazily for performance reasons
    if (!static_zone_is_initalized(state)) {
        err = initialize_static_zone(state);
        if (err_is_fail(err)) {
            goto finish_refill;
        }
    }
    struct capref cap;
    size_t size = MORECORE_REFILL_SIZE;
    err = frame_alloc(&cap, size, &size);
    if (err_is_fail(err)) {
        goto finish_refill;
    }
    err = paging_map_fixed_attr(get_current_paging_state(),
                                state->static_zone.base_addr + state->static_zone.backed_size,
                                cap, size, VREGION_FLAGS_READ_WRITE);
    if (err_is_fail(err)) {
        goto finish_refill;
    }
    state->static_zone.backed_size += size;

    err = SYS_ERR_OK;
    finish_refill:
    state->static_zone.is_refilling = false;
    return err;

}

static void *morecore_alloc_static(struct morecore_state *state, size_t bytes, size_t *retbytes)
{
    errval_t err;
    size_t aligned_bytes = ROUND_UP(bytes, sizeof(Header));
    void *ret = NULL;

    err = ensure_static_threshold(state, aligned_bytes);
    if (err_is_fail(err)) {
        *retbytes = 0;
        return ret;
    }

    if (state->freep + aligned_bytes < endp) {
        ret = state->freep;
        state->freep += aligned_bytes;
    }
    else {
        ret = (void *)state->static_zone.current_addr;
        state->static_zone.current_addr += aligned_bytes;
    }
    *retbytes = aligned_bytes;
    return ret;
}

static void *morecore_alloc_dynamic(struct morecore_state *state, size_t bytes, size_t *retbytes)
{
    errval_t err;

    void *ret_addr = NULL;

    err = paging_region_map(&state->dynamic_heap_pr, bytes, &ret_addr, retbytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_region_map()");
        return NULL;
    }

    assert(*retbytes >= bytes);

    return ret_addr;
}

/**
 * \brief Allocate some memory for malloc to use
 *
 * This function will keep trying with smaller and smaller frames till
 * it finds a set of frames that satisfy the requirement. retbytes can
 * be smaller than bytes if we were able to allocate a smaller memory
 * region than requested for.
 */
static void *morecore_alloc(size_t bytes, size_t *retbytes)
{
    struct morecore_state *state = get_morecore_state();
    bytes = MAX(bytes, MORECORE_ALLOC_GRANULARITY);
    if (state->heap_static) {
        return morecore_alloc_static(state, bytes, retbytes);
    } else {
        return morecore_alloc_dynamic(state, bytes, retbytes);
    }
}

static void morecore_free(void *base, size_t bytes)
{
    USER_PANIC("NYI \n");
}


static void morecore_init_dynamic(struct morecore_state *state, size_t alignment)
{
    errval_t err;

    void *buf;

    err = paging_region_init_aligned(
        get_current_paging_state(),
        &state->dynamic_heap_pr,
        MORECORE_VADDR_ZONE_SIZE,
        alignment,
        VREGION_FLAGS_READ_WRITE
    );

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_region_init_aligned()");
    }

    buf = &state->dynamic_heap_pr.node->base;

    state->dynamic_zone.region_size = MORECORE_VADDR_ZONE_SIZE;
    state->dynamic_zone.base_addr = (lvaddr_t) buf;
    state->dynamic_zone.current_addr = state->dynamic_zone.base_addr;
    state->header_freep_dynamic = NULL;
}

void morecore_enable_static(void)
{
    struct morecore_state *state = get_morecore_state();
    if (!state->heap_static) {
        state->heap_static = true;

        state->header_freep_dynamic = state->header_freep;
        state->header_base_dynamic = state->header_base;

        state->header_freep = state->header_freep_static;
        state->header_base = state->header_base_static;
    }
}

void morecore_enable_dynamic(void)
{
    struct morecore_state *state = get_morecore_state();
    if (state->heap_static) {
        state->heap_static = false;

        state->header_freep_static = state->header_freep;
        state->header_base_static = state->header_base;

        state->header_freep = state->header_freep_dynamic;
        state->header_base = state->header_base_dynamic;
    }
}

errval_t morecore_init(size_t alignment)
{
    struct morecore_state *state = get_morecore_state();
    memset(state, 0, sizeof(struct morecore_state));

    //thread_mutex_init(state->mutex);
    state->mutex = &get_current_paging_state()->mutex;

    // we start off dynamic and switch to static in pagefault handler

    // XXX: Glue aos_malloc which is static/dynamic heap aware
    // no malloc before this function is called as we initialize morecore here

    alt_free = aos_free;
    alt_free_locked = __aos_free_locked;
    alt_malloc = aos_malloc;

    sys_morecore_alloc = morecore_alloc;
    sys_morecore_free = morecore_free;

    state->heap_static = false;

    morecore_init_static(state, alignment);
    morecore_enable_static();
    morecore_init_dynamic(state,alignment);
    morecore_enable_dynamic();

    return SYS_ERR_OK;
}

errval_t morecore_reinit(void)
{
    USER_PANIC("NYI \n");
    return SYS_ERR_OK;
}

#endif

Header *get_malloc_freep(void);
Header *get_malloc_freep(void)
{
    struct morecore_state *state = get_morecore_state();
    return state->header_freep;
}
