/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _SSAM_SSH_PACKET_LAYER_H
#define _SSAM_SSH_PACKET_LAYER_H

#include <linux/atomic.h>
#include <linux/kfifo.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/serdev.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include <linux/surface_aggregator_module.h>

#include "ssh_msgb.h"
#include "ssh_parser.h"


enum ssh_ptl_state_flags {
	SSH_PTL_SF_SHUTDOWN_BIT,
};

struct ssh_ptl_ops {
	void (*data_received)(struct ssh_ptl *p, const struct ssam_span *data);
};

struct ssh_ptl {
	struct serdev_device *serdev;
	unsigned long state;

	struct {
		spinlock_t lock;
		struct list_head head;
	} queue;

	struct {
		spinlock_t lock;
		struct list_head head;
		atomic_t count;
	} pending;

	struct {
		bool thread_signal;
		struct task_struct *thread;
		struct wait_queue_head thread_wq;
		struct wait_queue_head packet_wq;
		struct ssh_packet *packet;
		size_t offset;
	} tx;

	struct {
		struct task_struct *thread;
		struct wait_queue_head wq;
		struct kfifo fifo;
		struct sshp_buf buf;

		struct {
			u16 seqs[8];
			u16 offset;
		} blocked;
	} rx;

	struct {
		ktime_t timeout;
		ktime_t expires;
		struct delayed_work reaper;
	} rtx_timeout;

	struct ssh_ptl_ops ops;
};

struct ssh_packet_args {
	unsigned long type;
	u8 priority;
	const struct ssh_packet_ops *ops;
};


#define __ssam_prcond(func, p, fmt, ...)		\
	do {						\
		if ((p))				\
			func((p), fmt, ##__VA_ARGS__);	\
	} while (0);

#define ptl_dbg(p, fmt, ...)  dev_dbg(&(p)->serdev->dev, fmt, ##__VA_ARGS__)
#define ptl_info(p, fmt, ...) dev_info(&(p)->serdev->dev, fmt, ##__VA_ARGS__)
#define ptl_warn(p, fmt, ...) dev_warn(&(p)->serdev->dev, fmt, ##__VA_ARGS__)
#define ptl_err(p, fmt, ...)  dev_err(&(p)->serdev->dev, fmt, ##__VA_ARGS__)
#define ptl_dbg_cond(p, fmt, ...) __ssam_prcond(ptl_dbg, p, fmt, ##__VA_ARGS__)

#define to_ssh_ptl(ptr, member) \
	container_of(ptr, struct ssh_ptl, member)


int ssh_ptl_init(struct ssh_ptl *ptl, struct serdev_device *serdev,
		 struct ssh_ptl_ops *ops);

void ssh_ptl_destroy(struct ssh_ptl *ptl);

static inline struct device *ssh_ptl_get_device(struct ssh_ptl *ptl)
{
	return ptl->serdev ? &ptl->serdev->dev : NULL;
}

int ssh_ptl_tx_start(struct ssh_ptl *ptl);
int ssh_ptl_rx_start(struct ssh_ptl *ptl);
void ssh_ptl_shutdown(struct ssh_ptl *ptl);

int ssh_ptl_submit(struct ssh_ptl *ptl, struct ssh_packet *p);
void ssh_ptl_cancel(struct ssh_packet *p);

int ssh_ptl_rx_rcvbuf(struct ssh_ptl *ptl, const u8 *buf, size_t n);
void ssh_ptl_tx_wakeup(struct ssh_ptl *ptl, bool force);

void ssh_packet_init(struct ssh_packet *packet,
		     const struct ssh_packet_args *args);

int ssh_ctrl_packet_cache_init(void);
void ssh_ctrl_packet_cache_destroy(void);

#endif /* _SSAM_SSH_PACKET_LAYER_H */
