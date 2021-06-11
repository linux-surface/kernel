/*
 * spi-hid-pool.h
 *
 * Copyright (c) 2020 Microsoft Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#ifndef SPI_HID_POOL_H
#define SPI_HID_POOL_H

#include <linux/atomic.h>

/*
 * - spi_hid_pool -
 * memory pool to hold N<=16 input reports to be processed by the client.
 * one producer (spi input report sequence) and two concurrent consumers
 * (input_report_pop) and (response_take).
 */

/*
 * pending_list stores a list of 4 bit indices of pending input reports
 *   in low bits older order
 * buf is a pointer to the underlying report buffer
 * e_size is the size of a report / element
 * bitmap store the state free(0)/allocated(1) for each slot
 * n_pending is the number of reports in the pending_list
 * report, response and input are indices into the bitmap
 * input_report is the currently pop:ed input report, it is is deallocated
 *   and returned to the pool by the consumer when a new input_report is popped
 * response is the currently active response, by spec only one response may be
 *    pending at a time, so when a new response arrives we can assume the
 *    client has requested a new response and is done with the currently active
 *    one.
 * input is the current input buffer which data may be written to.
 * lock is protecting the whole data structure
 */
struct spi_hid_pool {
	int *pending_list;
	void *buf;
	u8 buffers_allocated;
	u16 e_size;
	uint n_elem;
	uint bitmap;
	uint next;
	uint last;
	int report;
	int response;
	atomic_t discarded;
	spinlock_t lock;
};

static inline void *spi_hid_pool_idx_to_ptr(struct spi_hid_pool *pool, uint idx)
{
	return pool->buf + (idx * (size_t)pool->e_size);
}

static inline int spi_hid_pool_ptr_to_idx(struct spi_hid_pool *pool, void *ptr)
{
	return (ptr - pool->buf) / (size_t)pool->e_size;
}

// find highest slot index with status 0 (fls finds highest 1, invert bitmap)
// fls is one idexed (so lowest bit set = 1), so subtract 1 to get bitmap idx
// set the bit to one to indicate taken.
static inline int spi_hid_pool_take(struct spi_hid_pool *pool)
{
	int idx = fls((~pool->bitmap) & ((1 << pool->n_elem) - 1)) - 1;
	if (idx > 0 && idx < pool->n_elem) {
		pool->bitmap |= 1 << idx;
	} else {
		/* Out of buffers */
		idx = -1;
	}
	return idx;
}

static inline void spi_hid_pool_release(struct spi_hid_pool *pool, int idx)
{
	pool->bitmap &= ~(1 << idx);
}

static inline void spi_hid_pool_push(struct spi_hid_pool *pool, int idx)
{
	pool->pending_list[pool->next++] = idx;
	if (pool->next >= pool->n_elem) {
		pool->next = 0;
	}

	if (pool->next == pool->last) {
		pool->last++;
		if (pool->last >= pool->n_elem) {
			pool->last = 0;
		}
	}
}

static inline int spi_hid_pool_pop(struct spi_hid_pool *pool)
{
	int idx = -1;

	if (pool->last != pool->next) {
		idx = pool->pending_list[pool->last++];
		if (pool->last >= pool->n_elem) {
			pool->last = 0;
		}
	}

	return idx;
}

static inline void spi_hid_pool_push_report(struct spi_hid_pool *pool, void *ptr)
{
	unsigned long flags;
	int input;

	spin_lock_irqsave(&pool->lock, flags);
	input = spi_hid_pool_ptr_to_idx(pool, ptr);
	spi_hid_pool_push(pool, input);
	spin_unlock_irqrestore(&pool->lock, flags);
}

static inline void spi_hid_pool_push_response(struct spi_hid_pool *pool, void *ptr)
{
	unsigned long flags;
	spin_lock_irqsave(&pool->lock, flags);
	spi_hid_pool_release(pool, pool->response);
	pool->response = spi_hid_pool_ptr_to_idx(pool, ptr);
	spin_unlock_irqrestore(&pool->lock, flags);
}

static inline void spi_hid_pool_pop_report(struct spi_hid_pool *pool, void **buf)
{
	unsigned long flags;
	spin_lock_irqsave(&pool->lock, flags);
	if (pool->next != pool->last) {
		spi_hid_pool_release(pool, pool->report);
		pool->report = spi_hid_pool_pop(pool);
		*buf = spi_hid_pool_idx_to_ptr(pool, pool->report);
	} else {
		*buf = NULL;
	}
	spin_unlock_irqrestore(&pool->lock, flags);
}

// Assuming that no new response is expected until client explicitly requests
// one and will not fetch it until after notified, no locking needed here.
static inline void *spi_hid_pool_pop_response(struct spi_hid_pool *pool)
{
	return spi_hid_pool_idx_to_ptr(pool, pool->response);
}

static inline void *spi_hid_pool_take_input(struct spi_hid_pool *pool)
{
	unsigned long flags;
	int input;

	spin_lock_irqsave(&pool->lock, flags);

	input = spi_hid_pool_take(pool);
	if (input < 0) {
		input = spi_hid_pool_pop(pool);
		atomic_inc(&pool->discarded);
	}

	spin_unlock_irqrestore(&pool->lock, flags);

	return spi_hid_pool_idx_to_ptr(pool, input);
}

static inline void spi_hid_pool_drop_input(struct spi_hid_pool *pool, void *ptr)
{
        unsigned long flags;
        int input = spi_hid_pool_ptr_to_idx(pool, ptr);

        spin_lock_irqsave(&pool->lock, flags);
        spi_hid_pool_release(pool, input);
        spin_unlock_irqrestore(&pool->lock, flags);
}

static inline int spi_hid_pool_get_discarded(struct spi_hid_pool *pool)
{
	return atomic_xchg(&pool->discarded, 0);
}

static inline int spi_hid_pool_init(struct spi_hid_pool *pool, uint n,
		size_t element_size, gfp_t flags)
{
	pool->bitmap = 0;
	pool->next = 0;
	pool->last = 0;
	atomic_set(&pool->discarded, 0);

	/* bitmap is uint so this can handle up to that may buffers with a bitmap, minimum 4 */
	if (n > (sizeof(uint)*8 - 1) || n < 4) return -EINVAL;

        /* Check if buffers are already allocated or size has changed */
        if (!pool->buffers_allocated || !pool->buf || !pool->pending_list ||
                pool->e_size != element_size || pool->n_elem != n) {
                pool->buffers_allocated = 0;
                if (pool->buf) {
                    kfree(pool->buf);
                    pool->buf = NULL;
                }
                if (pool->pending_list) {
                    kfree(pool->pending_list);
                    pool->pending_list = NULL;
                }

                pool->buf = kzalloc(n * element_size, flags);
                if (!pool->buf) return -ENOMEM;

                pool->pending_list = kzalloc(n * sizeof(int), flags);
                if (!pool->pending_list) {
                    kfree(pool->buf);
                    pool->buf = 0;
                    return -ENOMEM;
                }
                pool->buffers_allocated = 1;
        }
	pool->e_size = element_size;
	pool->n_elem = n;

	spin_lock_init(&pool->lock);

	pool->report = spi_hid_pool_take(pool);
	pool->response = spi_hid_pool_take(pool);
	return 0;
}

static inline int spi_hid_pool_reset(struct spi_hid_pool *pool)
{
	pool->next = 0;
	pool->last = 0;
	pool->bitmap = 0;
	atomic_set(&pool->discarded, 0);
        if (!pool->buffers_allocated || !pool->buf || !pool->pending_list) {
            return 1;
        }
        memset(pool->buf, 0, pool->n_elem * pool->e_size);
        memset(pool->pending_list, 0, pool->n_elem * sizeof(int));
        memset(&pool->lock, 0, sizeof(spinlock_t)); // TODO: needed?
        return 0;
}

static inline void spi_hid_pool_destroy(struct spi_hid_pool *pool)
{
        pool->buffers_allocated = 0;
	if (pool->buf != 0) {
		kfree(pool->buf);
	}
	if (pool->pending_list != 0) {
		kfree(pool->pending_list);
	}
	memset(pool, 0, sizeof(struct spi_hid_pool));
}

#endif
