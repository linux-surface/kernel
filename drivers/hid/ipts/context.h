/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2020-2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#ifndef IPTS_CONTEXT_H
#define IPTS_CONTEXT_H

#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/device.h>
#include <linux/hid.h>
#include <linux/kref.h>
#include <linux/mei_cl_bus.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "mei.h"
#include "resources.h"
#include "spec-device.h"
#include "thread.h"

struct ipts_context {
	struct device *dev;
	struct ipts_mei mei;

	enum ipts_mode mode;

	/*
	 * Prevents concurrent GET_FEATURE reports.
	 */
	struct mutex feature_lock;
	struct completion feature_event;

	/*
	 * These are not inside of struct ipts_resources
	 * because they don't own the memory they point to.
	 */
	struct ipts_buffer feature_report;
	struct ipts_buffer descriptor;

	bool hid_active;
	struct hid_device *hid;

	/*
	 * Serializes a restart with remove. Restarts requested from a HID callback (the EDS1
	 * mode switch) run from restart_work, never inside the callback.
	 */
	struct mutex ctl_lock;
	struct work_struct restart_work;
	bool removing;

	/*
	 * Freed when the last reference is dropped. Probe holds one (dropped by devres), and the
	 * receiver thread, the HID device, every holder of message_lock and a queued restart
	 * hold one each.
	 */
	struct kref refcount;

	/*
	 * Users other than probe. ipts_remove() waits, bounded, for this to reach zero. That
	 * narrows the window in which the module code is freed under a user that is about to
	 * return, but does not close it: the last user wakes remove from inside its own put.
	 */
	atomic_t users;
	wait_queue_head_t users_wq;

	struct ipts_device_info info;
	struct ipts_resources resources;

	struct ipts_thread receiver_loop;
};

void ipts_context_release(struct kref *refcount);

/*
 * Every user of the context (the receiver thread, the HID device, a holder of message_lock, a
 * queued restart) takes a reference, so the context is freed only after the last user is gone.
 */
static inline void ipts_context_get(struct ipts_context *ipts)
{
	if (!ipts)
		return;

	kref_get(&ipts->refcount);
	atomic_inc(&ipts->users);
}

static inline void ipts_context_put(struct ipts_context *ipts)
{
	if (!ipts)
		return;

	if (atomic_dec_and_test(&ipts->users))
		wake_up_all(&ipts->users_wq);

	kref_put(&ipts->refcount, ipts_context_release);
}

#endif /* IPTS_CONTEXT_H */
