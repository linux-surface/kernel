/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _SSAM_CONTROLLER_H
#define _SSAM_CONTROLLER_H

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/serdev.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include <linux/surface_aggregator_module.h>

#include "ssh_protocol.h"
#include "ssh_request_layer.h"


/* -- Safe counters. -------------------------------------------------------- */

struct ssh_seq_counter {
	u8 value;
};

struct ssh_rqid_counter {
	u16 value;
};


/* -- Event/notification system. -------------------------------------------- */

struct ssam_nf_head {
	struct srcu_struct srcu;
	struct ssam_notifier_block __rcu *head;
};

struct ssam_nf {
	struct mutex lock;
	struct rb_root refcount;
	struct ssam_nf_head head[SSH_NUM_EVENTS];
};


/* -- Event/async request completion system. -------------------------------- */

struct ssam_cplt;
struct ssam_event_item;

struct ssam_event_item_ops {
	void (*free)(struct ssam_event_item *);
};

struct ssam_event_item {
	struct list_head node;
	u16 rqid;

	struct ssam_event_item_ops ops;
	struct ssam_event event;	// must be last
};

struct ssam_event_queue {
	struct ssam_cplt *cplt;

	spinlock_t lock;
	struct list_head head;
	struct work_struct work;
};

struct ssam_event_channel {
	struct ssam_event_queue queue[SSH_NUM_EVENTS];
};

struct ssam_cplt {
	struct device *dev;
	struct workqueue_struct *wq;

	struct {
		struct ssam_event_channel channel[SSH_NUM_CHANNELS];
		struct ssam_nf notif;
	} event;
};


/* -- Main SSAM device structures. ------------------------------------------ */

enum ssam_controller_state {
	SSAM_CONTROLLER_UNINITIALIZED,
	SSAM_CONTROLLER_INITIALIZED,
	SSAM_CONTROLLER_STARTED,
	SSAM_CONTROLLER_STOPPED,
	SSAM_CONTROLLER_SUSPENDED,
};

struct ssam_device_caps {
	u32 notif_display:1;
	u32 notif_d0exit:1;
};

struct ssam_controller {
	struct kref kref;

	struct rw_semaphore lock;
	enum ssam_controller_state state;

	struct ssh_rtl rtl;
	struct ssam_cplt cplt;

	struct {
		struct ssh_seq_counter seq;
		struct ssh_rqid_counter rqid;
	} counter;

	struct {
		int num;
		bool wakeup_enabled;
	} irq;

	struct ssam_device_caps caps;
};

#define to_ssam_controller(ptr, member) \
	container_of(ptr, struct ssam_controller, member)

#define ssam_dbg(ctrl, fmt, ...)  rtl_dbg(&(ctrl)->rtl, fmt, ##__VA_ARGS__)
#define ssam_info(ctrl, fmt, ...) rtl_info(&(ctrl)->rtl, fmt, ##__VA_ARGS__)
#define ssam_warn(ctrl, fmt, ...) rtl_warn(&(ctrl)->rtl, fmt, ##__VA_ARGS__)
#define ssam_err(ctrl, fmt, ...)  rtl_err(&(ctrl)->rtl, fmt, ##__VA_ARGS__)


static inline
int ssam_controller_receive_buf(struct ssam_controller *ctrl,
				const unsigned char *buf, size_t n)
{
	return ssh_ptl_rx_rcvbuf(&ctrl->rtl.ptl, buf, n);
}

static inline void ssam_controller_write_wakeup(struct ssam_controller *ctrl)
{
	ssh_ptl_tx_wakeup(&ctrl->rtl.ptl, true);
}


int ssam_controller_init(struct ssam_controller *ctrl, struct serdev_device *s);
int ssam_controller_start(struct ssam_controller *ctrl);
void ssam_controller_shutdown(struct ssam_controller *ctrl);
void ssam_controller_destroy(struct ssam_controller *ctrl);

int ssam_irq_setup(struct ssam_controller *ctrl);
void ssam_irq_free(struct ssam_controller *ctrl);

void ssam_controller_lock(struct ssam_controller *c);
void ssam_controller_unlock(struct ssam_controller *c);

int ssam_log_firmware_version(struct ssam_controller *ctrl);
int ssam_ctrl_notif_display_off(struct ssam_controller *ctrl);
int ssam_ctrl_notif_display_on(struct ssam_controller *ctrl);
int ssam_ctrl_notif_d0_exit(struct ssam_controller *ctrl);
int ssam_ctrl_notif_d0_entry(struct ssam_controller *ctrl);

int ssam_controller_suspend(struct ssam_controller *ctrl);
int ssam_controller_resume(struct ssam_controller *ctrl);

int ssam_event_item_cache_init(void);
void ssam_event_item_cache_destroy(void);

#endif /* _SSAM_CONTROLLER_H */
