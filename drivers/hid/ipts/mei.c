// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mei_cl_bus.h>
#include <linux/printk.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "context.h"
#include "mei.h"

/*
 * The message lock is only ever held around a list add or delete. A holder that keeps it
 * for longer died or is stuck, and waiting for it must never block forever: ipts_remove()
 * runs on reboot and suspend, too.
 */
static bool ipts_mei_trylock(struct ipts_mei *mei)
{
	struct ipts_context *ipts = container_of(mei, struct ipts_context, mei);

	if (!down_write_trylock(&mei->message_lock))
		return false;

	/*
	 * Hold the context while the lock is held, so a holder that never releases the lock (a
	 * dead or stuck task) keeps the context alive instead of freeing it under itself.
	 */
	ipts_context_get(ipts);

	return true;
}

static bool ipts_mei_lock_timeout(struct ipts_mei *mei, unsigned int timeout_ms)
{
	unsigned long end = jiffies + msecs_to_jiffies(timeout_ms);

	while (!ipts_mei_trylock(mei)) {
		if (time_after(jiffies, end))
			return false;

		usleep_range(IPTS_MEI_LOCK_POLL_US, 2 * IPTS_MEI_LOCK_POLL_US);
	}

	return true;
}

static void ipts_mei_unlock(struct ipts_mei *mei)
{
	struct ipts_context *ipts = container_of(mei, struct ipts_context, mei);

	/*
	 * Release the lock before the reference: if this is the last one, the release function
	 * frees the context, and takes the lock itself to free the messages.
	 */
	up_write(&mei->message_lock);
	ipts_context_put(ipts);
}

/*
 * Read one response from the bus and queue it. Returns false if none was ready within
 * IPTS_MEI_RECV_MORE_MS or reading it failed.
 */
static bool ipts_mei_receive(struct ipts_context *ipts, struct mei_cl_device *cldev)
{
	ssize_t ret = 0;
	struct ipts_mei_message *entry = NULL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return false;

	INIT_LIST_HEAD(&entry->list);

	do {
		ret = mei_cldev_recv_timeout(cldev, (u8 *)&entry->rsp, sizeof(entry->rsp),
					     IPTS_MEI_RECV_MORE_MS);
	} while (ret == -EINTR);

	if (ret == -ETIME) {
		kfree(entry);
		return false;
	}

	if (ret < 0) {
		dev_err(ipts->dev, "Error while reading response: %ld\n", ret);
		kfree(entry);
		return false;
	}

	if (ret == 0) {
		dev_err(ipts->dev, "Received empty response\n");
		kfree(entry);
		return false;
	}

	if (!ipts_mei_lock_timeout(&ipts->mei, IPTS_MEI_LOCK_TIMEOUT_MS)) {
		dev_err_ratelimited(ipts->dev, "Message lock is busy, dropping a response\n");
		kfree(entry);
		return true;
	}

	list_add(&entry->list, &ipts->mei.messages);
	WRITE_ONCE(ipts->mei.seq, ipts->mei.seq + 1);
	ipts_mei_unlock(&ipts->mei);

	wake_up_all(&ipts->mei.message_queue);
	return true;
}

static void ipts_mei_incoming(struct mei_cl_device *cldev)
{
	struct ipts_context *ipts = NULL;

	if (!cldev) {
		pr_err("MEI device is NULL!");
		return;
	}

	ipts = mei_cldev_get_drvdata(cldev);
	if (!ipts) {
		pr_err("IPTS driver context is NULL!");
		return;
	}

	/*
	 * The bus calls this from a work item that it schedules when a response arrives. IPTS
	 * is a fixed-address client, so the ME can send the next response before that work has
	 * run, and scheduling it again then does nothing: one call, two responses ready. If
	 * only one was read, the other would wait with the bus until a later response arrives.
	 * When stopping, that is the QUIESCE_IO response, right behind the one for the pending
	 * READY_FOR_DATA, and the stop is never confirmed. So read until none is ready. The
	 * wait for each is bounded, so a call whose response an earlier call took returns too.
	 */
	while (ipts_mei_receive(ipts, cldev))
		;
}

static int ipts_mei_search(struct ipts_mei *mei, enum ipts_command_code code,
			   struct ipts_response *rsp)
{
	struct ipts_mei_message *entry = NULL;

	if (!mei)
		return -EFAULT;

	if (!rsp)
		return -EFAULT;

	if (!ipts_mei_trylock(mei))
		return -EBUSY;

	/*
	 * Iterate over the list of received messages, and check if there is one
	 * matching the requested command code.
	 */
	list_for_each_entry(entry, &mei->messages, list) {
		if (entry->rsp.cmd == code)
			break;
	}

	/*
	 * If entry is not the list head, this means that the loop above has been stopped early,
	 * and that we found a matching element. We drop the message from the list while still
	 * holding the lock, so that no other waiter can claim the same entry, and return it.
	 */
	if (!list_entry_is_head(entry, &mei->messages, list)) {
		list_del(&entry->list);
		ipts_mei_unlock(mei);

		*rsp = entry->rsp;
		kfree(entry);

		return 0;
	}

	ipts_mei_unlock(mei);

	return -EAGAIN;
}

int ipts_mei_recv(struct ipts_mei *mei, enum ipts_command_code code, struct ipts_response *rsp,
		  u64 timeout)
{
	int ret = 0;
	long left = 0;
	unsigned long seq = 0;
	unsigned long end = 0;

	if (!mei)
		return -EFAULT;

	/*
	 * A timeout of 0 means check and return immediately.
	 */
	if (timeout == 0) {
		ret = ipts_mei_search(mei, code, rsp);
		return ret == -EBUSY ? -EAGAIN : ret;
	}

	end = jiffies + msecs_to_jiffies(timeout);

	/*
	 * Search with the task running, then sleep until a new message is queued or the time
	 * is up. seq is read before the search, so a message queued in between ends the sleep
	 * at once. While another task holds the lock, try again after a short sleep.
	 */
	do {
		seq = READ_ONCE(mei->seq);
		/* Read the sequence before searching for a message. */
		smp_rmb();

		ret = ipts_mei_search(mei, code, rsp);
		if (ret != -EAGAIN && ret != -EBUSY)
			return ret;

		left = (long)(end - jiffies);
		if (left <= 0)
			break;

		if (ret == -EBUSY)
			usleep_range(IPTS_MEI_LOCK_POLL_US, 2 * IPTS_MEI_LOCK_POLL_US);
		else
			wait_event_timeout(mei->message_queue, READ_ONCE(mei->seq) != seq, left);
	} while (left > 0);

	return -EAGAIN;
}

int ipts_mei_send(struct ipts_mei *mei, void *data, size_t length)
{
	ssize_t ret = 0;

	if (!mei)
		return -EFAULT;

	if (!mei->cldev)
		return -EFAULT;

	if (!data)
		return -EFAULT;

	/*
	 * Bounded: a send that is not acknowledged in time fails. An interrupted send is not
	 * retried, because the message is already queued and would go out twice.
	 */
	ret = mei_cldev_send_timeout(mei->cldev, (u8 *)data, length, IPTS_MEI_SEND_TIMEOUT_MS);

	if (ret < 0)
		return ret;

	return 0;
}

void ipts_mei_free_messages(struct ipts_mei *mei)
{
	struct ipts_mei_message *entry = NULL;
	struct ipts_mei_message *tmp = NULL;

	if (!mei)
		return;

	/*
	 * Only called when the context is released, so every holder of the lock dropped its
	 * reference and the lock is free, unless its holder died with it: then the messages are
	 * leaked rather than freed under it. The raw lock is taken, so no reference is taken on
	 * the context being released.
	 */
	if (!down_write_trylock(&mei->message_lock))
		return;

	list_for_each_entry_safe(entry, tmp, &mei->messages, list) {
		list_del(&entry->list);
		kfree(entry);
	}

	up_write(&mei->message_lock);
}

size_t ipts_mei_flush(struct ipts_mei *mei)
{
	size_t count = 0;
	struct ipts_mei_message *entry = NULL;
	struct ipts_mei_message *tmp = NULL;

	if (!mei)
		return 0;

	if (!ipts_mei_lock_timeout(mei, IPTS_MEI_LOCK_TIMEOUT_MS))
		return 0;

	list_for_each_entry_safe(entry, tmp, &mei->messages, list) {
		list_del(&entry->list);
		kfree(entry);
		count++;
	}

	ipts_mei_unlock(mei);

	return count;
}

int ipts_mei_reconnect(struct ipts_mei *mei)
{
	int ret = 0;

	if (!mei)
		return -EFAULT;

	if (!mei->cldev)
		return -EFAULT;

	/*
	 * This also unregisters the receive callback, and fails only if the client was already
	 * gone. Try to connect anyway.
	 */
	mei_cldev_disable(mei->cldev);

	ret = mei_cldev_enable(mei->cldev);
	if (ret)
		return ret;

	return mei_cldev_register_rx_cb(mei->cldev, ipts_mei_incoming);
}

int ipts_mei_init(struct ipts_mei *mei, struct mei_cl_device *cldev)
{
	if (!mei)
		return -EFAULT;

	if (!cldev)
		return -EFAULT;

	mei->cldev = cldev;
	mei->seq = 0;

	INIT_LIST_HEAD(&mei->messages);
	init_waitqueue_head(&mei->message_queue);
	init_rwsem(&mei->message_lock);

	mei_cldev_register_rx_cb(cldev, ipts_mei_incoming);

	return 0;
}
