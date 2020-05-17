//
// Created by b on 5/16/20.
//

#include "circular_buf.h"

__unused
static void cbuf_advance(struct cbuf *buf)
{
    if (buf->full) {
        buf->tail = (buf->tail + 1) % buf->max;
        CBUF_DEBUG("read buffer is full\n");
    }
    buf->head = (buf->head + 1) % buf->max;
    buf->full = buf->head == buf->tail;
}

__unused
static void cbuf_retreat(struct cbuf *buf)
{
    buf->tail = (buf->tail + 1) % buf->max;
    buf->full = false;
}

void cbuf_put(struct cbuf *buf, void *data_entry)
{
    memcpy((buf->data + buf->head * buf->entry_size), data_entry, buf->entry_size);
    // memcpy(&buf->data[buf->head * buf->entry_size], data_entry, buf->entry_size);
    cbuf_advance(buf);
}

errval_t cbuf_put2(struct cbuf *buf, void *data_entry)
{
    if (buf->full) {
        return LIB_ERR_NOT_IMPLEMENTED; // TODO: buffer is full
    }
    memcpy((buf->data + buf->head * buf->entry_size), data_entry, buf->entry_size);
    // memcpy(&buf->data[buf->head * buf->entry_size], data_entry, buf->entry_size);
    cbuf_advance(buf);

    return SYS_ERR_OK;
}


errval_t cbuf_get(struct cbuf *buf, void **ret_data)
{
    if (cbuf_empty(buf)) {
        return LPUART_ERR_NO_DATA; // TODO: buffer is empty
    }
    *ret_data = buf->data + (buf->tail * buf->entry_size);
    cbuf_retreat(buf);

    return SYS_ERR_OK;
}

errval_t
cbuf_init(struct cbuf *buf, void *data, size_t entry_size, size_t max_entries)
{
    assert(buf != NULL);
    assert(data != NULL);
    assert(max_entries > 0);
    assert(entry_size > 0);

    memset(buf, 0, sizeof(struct cbuf));
    memset(data, 0, max_entries * entry_size);
    buf->max = max_entries;
    buf->entry_size = entry_size;

    return SYS_ERR_OK;
};