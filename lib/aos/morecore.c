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

typedef void *(*morecore_alloc_func_t)(size_t bytes, size_t *retbytes);
extern morecore_alloc_func_t sys_morecore_alloc;

typedef void (*morecore_free_func_t)(void *base, size_t bytes);
extern morecore_free_func_t sys_morecore_free;

// this define makes morecore use an implementation that just has a static
// 16MB heap.
// TODO (M4): use a dynamic heap instead,
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

    thread_mutex_init(&state->mutex);

    state->freep = mymem;

    sys_morecore_alloc = morecore_alloc;
    sys_morecore_free = morecore_free;
    return SYS_ERR_OK;
}

errval_t morecore_reinit(void)
{
    return SYS_ERR_OK;
}

#else

#define HEAP_SIZE (1<<24)
static char mymem[HEAP_SIZE] = { 0 };
static char *endp = mymem + HEAP_SIZE;

static void morecore_init_static(struct morecore_state *state, size_t alignment)
{
    state->freep = mymem;
}

static void *morecore_alloc_static(struct morecore_state *state, size_t bytes, size_t *retbytes)
{
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


// dynamic heap using lib/aos/paging features

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
    void *ret_addr = NULL;
    const lvaddr_t end_address = state->zone.base_addr + state->zone.region_size;
    if (end_address <= state->zone.current_addr) {
        *retbytes = 0;
        debug_printf("morecore_alloc failed: out of zone addresses\n");
        return NULL;
    }

    lvaddr_t new_curr = MIN(state->zone.current_addr + bytes, end_address);
    if (new_curr < state->zone.current_addr) {
        *retbytes = 0;
        debug_printf("morecore_alloc failed: overflow\n");
        return NULL;
    }

    *retbytes = new_curr - state->zone.current_addr;
    ret_addr = (void *)state->zone.current_addr;
    state->zone.current_addr = new_curr;
    assert(new_curr <= end_address);

    return ret_addr;
}

static void morecore_free(void *base, size_t bytes)
{
    USER_PANIC("NYI \n");
}

errval_t morecore_init(size_t alignment)
{
    debug_printf("initializing dynamic heap\n");
    struct morecore_state *state = get_morecore_state();

    thread_mutex_init(&state->mutex);

    void *buf;
    paging_alloc(get_current_paging_state(), &buf, MORECORE_VADDR_ZONE_SIZE, BASE_PAGE_SIZE);
    state->zone.region_size = MORECORE_VADDR_ZONE_SIZE;
    state->zone.base_addr = (lvaddr_t)buf;
    state->zone.current_addr = state->zone.base_addr;

    sys_morecore_alloc = morecore_alloc;
    sys_morecore_free = morecore_free;

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
    return get_morecore_state()->header_freep;
}
