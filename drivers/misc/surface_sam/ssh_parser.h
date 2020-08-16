/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _SURFACE_SAM_SSH_PARSER_H
#define _SURFACE_SAM_SSH_PARSER_H

#include <linux/device.h>
#include <linux/kfifo.h>
#include <linux/slab.h>

#include <linux/surface_aggregator_module.h>


struct sshp_buf {
	u8    *ptr;
	size_t len;
	size_t cap;
};


static inline void sshp_buf_init(struct sshp_buf *buf, u8 *ptr, size_t cap)
{
	buf->ptr = ptr;
	buf->len = 0;
	buf->cap = cap;
}

static inline int sshp_buf_alloc(struct sshp_buf *buf, size_t cap, gfp_t flags)
{
	u8 *ptr;

	ptr = kzalloc(cap, flags);
	if (!ptr)
		return -ENOMEM;

	sshp_buf_init(buf, ptr, cap);
	return 0;

}

static inline void sshp_buf_free(struct sshp_buf *buf)
{
	kfree(buf->ptr);
	buf->ptr = NULL;
	buf->len = 0;
	buf->cap = 0;
}

static inline void sshp_buf_drop(struct sshp_buf *buf, size_t n)
{
	memmove(buf->ptr, buf->ptr + n, buf->len - n);
	buf->len -= n;
}

static inline size_t sshp_buf_read_from_fifo(struct sshp_buf *buf,
					     struct kfifo *fifo)
{
	size_t n;

	n =  kfifo_out(fifo, buf->ptr + buf->len, buf->cap - buf->len);
	buf->len += n;

	return n;
}

static inline void sshp_buf_span_from(struct sshp_buf *buf, size_t offset,
				      struct ssam_span *span)
{
	span->ptr = buf->ptr + offset;
	span->len = buf->len - offset;
}


bool sshp_find_syn(const struct ssam_span *src, struct ssam_span *rem);

int sshp_parse_frame(const struct device *dev, const struct ssam_span *source,
		     struct ssh_frame **frame, struct ssam_span *payload,
		     size_t maxlen);

int sshp_parse_command(const struct device *dev, const struct ssam_span *source,
		       struct ssh_command **command,
		       struct ssam_span *command_data);

#endif /* _SURFACE_SAM_SSH_PARSER_h */
