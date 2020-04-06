#ifndef _LIBC_AOS_MALLOC_H_
#define _LIBC_AOS_MALLOC_H_

#include <sys/cdefs.h>
#include <stddef.h>
#include "k_r_malloc.h"

#define MAGIC_STATIC  (0xB16B00B5)  /// < magic number used in addresses on static heap
#define MAGIC_DYNAMIC (0xB00BBABE)  /// < magic number used in addresses on dynamic heap

#define GET_MAGIC (state->heap_static ? MAGIC_STATIC : MAGIC_DYNAMIC)


// static/dynamic heap aware malloc implementation
typedef void *(*alt_malloc_t)(size_t bytes);
typedef void (*alt_free_t)(void *p);

void __aos_free_locked(void *ap);
void *aos_malloc(size_t nbytes);
void aos_free(void *ap);

#endif /* _LIBC_AOS_MALLOC_H_ */
