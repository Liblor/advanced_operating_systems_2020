
/*
 * K&R Malloc
 *
 * System specifc code should implement `more_core'
 */
#include "static_malloc.h"
#include <stddef.h> /* For NULL */
#include <stdlib.h>
#include <string.h> /* For memcpy */

#include <aos/aos.h>
#include <aos/core_state.h> /* XXX */
#include <aos/morecore.h>

#define STATIC_MALLOC_LOCK thread_mutex_lock(&state->static_mutex)
#define STATIC_MALLOC_UNLOCK thread_mutex_unlock(&state->static_mutex)

/*
 * malloc: general-purpose storage allocator
 */
void *static_malloc(size_t nbytes)
{
    struct morecore_state *state = get_morecore_state();
	Header *p, *prevp;
	unsigned nunits;
	nunits = (nbytes + sizeof(Header) - 1) / sizeof(Header) + 1;

	STATIC_MALLOC_LOCK;

    if ((prevp = state->header_freep_static) == NULL) {	/* no free list yet */
        state->header_base_static.s.ptr = state->header_freep_static = prevp = &state->header_base_static;
        state->header_base_static.s.size = 0;
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
            p->s.magic = MAGIC_STATIC;
            state->header_freep_static = prevp;

            STATIC_MALLOC_UNLOCK;
            return (void *) (p + 1);
        }
        if (p == state->header_freep_static) {	/* wrapped around free list */
            if ((p = (Header *) static_morecore(ROUND_UP(nunits, SNALLOC))) == NULL) {
                STATIC_MALLOC_UNLOCK;
                return NULL;	/* none left */
            } else {
            }
        }
    }
	STATIC_MALLOC_UNLOCK;
}


/*
 * stati_calloc: zero that stuff
 */
void *static_calloc(size_t nmemb, size_t size)
{
    void *p = static_malloc(size * nmemb);
    if (p != NULL) {
        memset(p, 0, size * nmemb);
    }
    return p;
}

/*
 * free: put block ap in free list
 */
void
__static_free_locked(void *ap)
{
    if (ap == NULL)
        return;

    struct morecore_state *state = get_morecore_state();
	Header *bp, *p;

	bp = (Header *) ap - 1;	/* point to block header */
	for (p = state->header_freep_static; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
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

	state->header_freep_static = p;

}

void static_free(void *ap)
{
    if (ap == NULL) {
        return;
    }
    struct morecore_state *state = get_morecore_state();
    if (((Header *)ap)[-1].s.magic != MAGIC_STATIC) {
        HERE;
        debug_printf("%s: Trying to free not malloced region %p by %p\n",
            __func__, ap, __builtin_return_address(0));
        return;
    }
    ((Header *)ap)[-1].s.magic = 0;
    STATIC_MALLOC_LOCK;
    __static_free_locked(ap);
    lesscore();
    STATIC_MALLOC_UNLOCK;
}
