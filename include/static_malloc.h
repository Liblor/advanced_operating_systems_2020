#ifndef _LIBC_STATIC_MALLOC_H
#define _LIBC_STATIC_MALLOC_H

#include <sys/cdefs.h>
#include <stddef.h> /* For NULL */
#include "k_r_malloc.h"

__BEGIN_DECLS

#define SNALLOC  0x1000		/* minimum #units to request */
#define MAGIC_STATIC  (0xB16B00B5)  /// < magic number used in addresses on static heap

#if 0
typedef long long Align;	/* for alignment to long long boundary */

union header {			/* block header */
	struct {
		union header   *ptr;	/* next block if on free list */
		unsigned		magic;  /* to mark malloced region */
		unsigned        size;	/* size of this block */
	} s;
	Align           x;	/* force alignment of blocks */
};

typedef union header Header;
#endif

Header *static_morecore(unsigned nu);
void __static_free_locked(void *ap);
void *static_malloc(size_t nbytes);
void *static_calloc(size_t nmemb, size_t size);
void static_free(void *ap);
int is_static_free(void *ap);

__END_DECLS

#endif /* _LIBC_STATIC_MALLOC_H */
