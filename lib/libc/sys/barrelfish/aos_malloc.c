
/*
 * AOS Malloc
 *
 * Malloc implementation which is aware of a static and dynamic heap
 */
#include "aos_malloc.h"
#include <stddef.h> /* For NULL */

#include <aos/aos.h>
#include <aos/core_state.h>

#define MALLOC_LOCK thread_mutex_lock_nested(state->mutex)
#define MALLOC_UNLOCK thread_mutex_unlock(state->mutex)

/*
 * malloc: general-purpose storage allocator
 */
void *aos_malloc(size_t nbytes)
{
    struct morecore_state *state = get_morecore_state();
	Header *p, *prevp;
	unsigned nunits;
	nunits = (nbytes + sizeof(Header) - 1) / sizeof(Header) + 1;

    assert(nbytes < MAX_MEM_ALLOC_SIZE);
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
	MALLOC_UNLOCK;
}

// free ap on given header_freep
static void
aos_free_locked_explicit(void *ap, Header **header_freep)
{
	Header *bp, *p;

	if (ap == NULL) {
        return;
	}

	bp = (Header *) ap - 1;	/* point to block header */
	for (p = *header_freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
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

	*header_freep = p;
}

/*
 * free: put block ap in free list
 */
void
__aos_free_locked(void *ap) {
    struct morecore_state *state = get_morecore_state();
    aos_free_locked_explicit(ap, &state->header_freep);
}

void aos_free(void *ap)
{
    if (ap == NULL) {
        return;
    }

    struct morecore_state *state = get_morecore_state();

    unsigned magic = ((Header *)ap)[-1].s.magic;

    if (magic != MAGIC_STATIC && magic != MAGIC_DYNAMIC) {
        debug_printf("%s: Trying to free not malloced region %p by %p\n",
                     __func__, ap, __builtin_return_address(0));
        assert(false);
        return;
    }

    ((Header *)ap)[-1].s.magic = 0;

    MALLOC_LOCK;

    /* XXX: we can be in a state where heap_static = true
       and a call to free() is performed with an addr
       that lies on the heap, i.e heap_static = false
       We need to use the correct morecore_state
       for this address. We pass header_freep by reference; */
    if (magic == MAGIC_STATIC) {
        state->header_freep = state->header_freep_static;
        aos_free_locked_explicit(ap, &state->header_freep);
        state->header_freep_static = state->header_freep ;
    } else {
        state->header_freep = state->header_freep_dynamic;
        aos_free_locked_explicit(ap, &state->header_freep);
        state->header_freep_dynamic = state->header_freep ;
    }
    state->header_freep = state->heap_static ? state->header_freep_static : state->header_freep_dynamic;

    lesscore();
    MALLOC_UNLOCK;
}
