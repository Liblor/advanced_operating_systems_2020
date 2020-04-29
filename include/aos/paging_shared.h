#ifndef _PAGING_SHARED_H_
#define _PAGING_SHARED_H_

#include <aos/caddr.h>

#define PAGING_LOCK thread_mutex_lock_nested(&st->mutex)
#define PAGING_UNLOCK thread_mutex_unlock(&st->mutex)

#endif
