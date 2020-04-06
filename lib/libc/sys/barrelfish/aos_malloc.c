
/*
 * AOS Malloc
 *
 * Malloc implementation which is aware of a static and dynamic heapx
 */

#include "aos_malloc.h"
#include <stddef.h> /* For NULL */

#include <aos/aos.h>
#include <aos/core_state.h> /* XXX */

#define MALLOC_LOCK thread_mutex_lock_nested(&state->mutex)
#define MALLOC_UNLOCK thread_mutex_unlock(&state->mutex)



/*
 * malloc: general-purpose storage allocator
 */
void *aos_malloc(size_t nbytes)
{
    // XXX: we dont use alt_malloc and alt_free anymore

    struct morecore_state *state = get_morecore_state();
//    if (state->heap_static) {
//        debug_printf("W\n");
//    }
	Header *p, *prevp;
	unsigned nunits;
	nunits = (nbytes + sizeof(Header) - 1) / sizeof(Header) + 1;

	MALLOC_LOCK;
	if ((prevp = state->header_freep) == NULL) {	/* no free list yet */
		state->header_base.s.ptr = state->header_freep = prevp = &state->header_base;
		state->header_base.s.size = 0;
	}
	for (p = prevp->s.ptr;; prevp = p, p = p->s.ptr) {
		if (p->s.size >= nunits) {	/* big enough */
			if (p->s.size == nunits)	/* exactly */
				prevp->s.ptr = p->s.ptr;
			else {	/* allocate tail end */
				p->s.size -= nunits;
				p += p->s.size;
				p->s.size = nunits;
			}
            p->s.magic = GET_MAGIC;
			state->header_freep = prevp;

			assert(state->heap_static && ((lvaddr_t)(p+1) < state->zone.base_addr));
			MALLOC_UNLOCK;
			return (void *) (p + 1);
		}
		if (p == state->header_freep) {	/* wrapped around free list */
			if ((p = (Header *) morecore(nunits)) == NULL) {
				MALLOC_UNLOCK;
				return NULL;	/* none left */
			} else {

			}
		}
	}
	HERE;
	MALLOC_UNLOCK;
}

/*
 * free: put block ap in free list
 */
void
__aos_free_locked(void *ap)
{
    struct morecore_state *state = get_morecore_state();
	Header *bp, *p;

	if (ap == NULL)
		return;

	bp = (Header *) ap - 1;	/* point to block header */
	for (p = state->header_freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
		if (p >= p->s.ptr && (bp > p || bp < p->s.ptr))
			break;	/* freed block at start or end of arena */

	if (bp + bp->s.size == p->s.ptr) {	/* join to upper nbr */
		bp->s.size += p->s.ptr->s.size;
		bp->s.ptr = p->s.ptr->s.ptr;
	} else {
		bp->s.ptr = p->s.ptr;
	}

	if (p + p->s.size == bp) {	/* join to lower nbr */
		p->s.size += bp->s.size;
		p->s.ptr = bp->s.ptr;
	} else {
		p->s.ptr = bp;
	}

	state->header_freep = p;
}

void aos_free(void *ap)
{
    if (ap == NULL) {
        return;
    }

    struct morecore_state *state = get_morecore_state();

    unsigned magic = ((Header *)ap)[-1].s.magic;

    if (magic != MAGIC_STATIC && magic != MAGIC_DYNAMIC) {
        assert(false);
        debug_printf("%s: Trying to free not malloced region %p by %p\n",
                     __func__, ap, __builtin_return_address(0));
        return;
    }

    ((Header *)ap)[-1].s.magic = 0;

    // XXX: we can be in a state where heap_static = true
    // and a call to free() is performed with an addr
    // that lies on the heap.
    // We need to use the appropriate morecore_state
    // for that address.
    Header cur_header_base = state->header_base;
    Header *cur_header_freep = state->header_freep;

    if (magic == MAGIC_STATIC) {
        state->header_base = state->header_base_static;
        state->header_freep = state->header_freep_static;
    } else {
        state->header_base = state->header_base_dynamic;
        state->header_freep = state->header_freep_dynamic;
    }
    MALLOC_LOCK;
    __aos_free_locked(ap);
    lesscore();

    // restore state
    state->header_base = cur_header_base;
    state->header_freep = cur_header_freep;

    MALLOC_UNLOCK;
}