//
// Created by b on 5/16/20.
//

#ifndef BFOS_CIRCULAR_BUF_H
#define BFOS_CIRCULAR_BUF_H

#include <aos/aos.h>
#include <stdio.h>

// #define CIRCULAR_BUF_DEBUG_ON
#if defined(CIRCULAR_BUF_DEBUG_ON)
#define CBUF_DEBUG(x...) debug_printf("cbuf: " x)
#else
#define CBUF_DEBUG(x...) ((void)0)
#endif


struct cbuf {
    bool full;
    size_t head;
    size_t tail;
    size_t max;
    size_t entry_size;
    void *data;
};

/// initialize a cbuffer
errval_t cbuf_init(struct cbuf *buf, void *data, size_t entry_size, size_t max_entries);

bool cbuf_empty(struct cbuf *buf);

// put and overwrite if full
void cbuf_put(struct cbuf *buf, void *data_entry);

void cbuf_reset(struct cbuf *buf);

// put only if space available, error otherwise
errval_t cbuf_put2(struct cbuf *buf, void *data);

errval_t cbuf_get(struct cbuf *buf, void **ret_data);

#endif //BFOS_CIRCULAR_BUF_H
