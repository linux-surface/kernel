// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020-2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#include <linux/delay.h>
#include <linux/err.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include <linux/types.h>

#include "cmd.h"
#include "context.h"
#include "control.h"
#include "hid.h"
#include "receiver.h"
#include "resources.h"
#include "spec-device.h"
#include "thread.h"

static void ipts_receiver_next_doorbell(struct ipts_context *ipts)
{
	u32 *doorbell = (u32 *)ipts->resources.doorbell.address;
	*doorbell = *doorbell + 1;
}

static u32 ipts_receiver_current_doorbell(struct ipts_context *ipts)
{
	u32 *doorbell = (u32 *)ipts->resources.doorbell.address;
	return *doorbell;
}

/*
 * Only the last IPTS_BUFFERS buffers can hold new data, so never walk further back than that,
 * whatever value the doorbell has. Returns the first buffer to look at.
 */
static u32 ipts_receiver_first_new(u32 doorbell, u32 lastdb)
{
	if ((s32)(doorbell - lastdb) < 0)
		return doorbell;

	if (doorbell - lastdb > IPTS_BUFFERS)
		return doorbell - IPTS_BUFFERS;

	return lastdb;
}

static void ipts_receiver_backoff(time64_t last, u32 n)
{
	/*
	 * If the last change was less than n seconds ago,
	 * sleep for a shorter period so that new data can be
	 * processed quickly. If there was no change for more than
	 * n seconds, sleep longer to avoid wasting CPU cycles.
	 */
	if (last + n > ktime_get_seconds())
		usleep_range(1 * USEC_PER_MSEC, 5 * USEC_PER_MSEC);
	else
		msleep(200);
}

/*
 * End of a receiver loop, after QUIESCE_IO was sent: collect the last READY_FOR_DATA reply,
 * then wait for the QUIESCE_IO confirmation, even if that reply was lost. Starting the
 * device again before it has stopped can leave its firmware unresponsive until the next
 * boot.
 *
 * Returns: 0 only if the device confirmed the stop. Otherwise the device may still write to
 * its buffers, and the caller must not free them.
 */
static int ipts_receiver_finish(struct ipts_context *ipts)
{
	int ret = 0;
	unsigned long end = 0;

	ret = ipts_control_wait_data(ipts, true);
	if (ret && ret != -EAGAIN)
		dev_err(ipts->dev, "Failed to wait for data: %d\n", ret);

	end = jiffies + msecs_to_jiffies(IPTS_RECEIVER_STOP_CONFIRM_MS);

	do {
		ret = ipts_control_wait_flush(ipts);
	} while (ret == -EAGAIN && time_before(jiffies, end));

	if (ret) {
		dev_err(ipts->dev, "Device did not confirm the stop: %d\n", ret);
		return ret == -EAGAIN ? -ETIMEDOUT : ret;
	}

	return 0;
}

/*
 * In poll mode, the device confirms QUIESCE_IO only after every buffer it filled was given
 * back. Give back the ones the loop did not get to, without passing their data on: HID input
 * is already disabled. The time is bounded, and the first failed feedback ends it.
 */
static void ipts_receiver_return_buffers(struct ipts_context *ipts, u32 lastdb)
{
	int ret = 0;
	u32 doorbell = ipts_receiver_current_doorbell(ipts);
	unsigned long end = jiffies + msecs_to_jiffies(IPTS_RECEIVER_STOP_CONFIRM_MS);

	lastdb = ipts_receiver_first_new(doorbell, lastdb);

	while (lastdb != doorbell && time_before(jiffies, end)) {
		ret = ipts_control_refill_buffer(ipts, lastdb % IPTS_BUFFERS);
		if (ret) {
			dev_err(ipts->dev, "Failed to send feedback: %d\n", ret);
			return;
		}

		lastdb++;
	}
}

static int ipts_receiver_event_loop(struct ipts_thread *thread)
{
	int ret = 0;
	u32 buffer = 0;

	struct ipts_context *ipts = NULL;
	time64_t last = ktime_get_seconds();

	if (!thread)
		return -EFAULT;

	ipts = thread->data;

	if (!ipts)
		return -EFAULT;

	dev_info(ipts->dev, "IPTS running in event mode\n");

	while (!ipts_thread_should_stop(thread)) {
		int i = 0;

		for (i = 0; i < IPTS_BUFFERS && !ipts_thread_should_stop(thread); i++) {
			ret = ipts_control_wait_data(ipts, false);
			if (ret == -EAGAIN)
				break;

			if (ret) {
				dev_err(ipts->dev, "Failed to wait for data: %d\n", ret);
				continue;
			}

			buffer = ipts_receiver_current_doorbell(ipts) % IPTS_BUFFERS;
			ipts_receiver_next_doorbell(ipts);

			ret = ipts_hid_input_data(ipts, buffer);
			if (ret)
				dev_err(ipts->dev, "Failed to process buffer: %d\n", ret);

			ret = ipts_control_refill_buffer(ipts, buffer);
			if (ret)
				dev_err(ipts->dev, "Failed to send feedback: %d\n", ret);

			ret = ipts_control_request_data(ipts);
			if (ret)
				dev_err(ipts->dev, "Failed to request data: %d\n", ret);

			last = ktime_get_seconds();
		}

		ipts_receiver_backoff(last, 5);
	}

	ret = ipts_control_request_flush(ipts);
	if (ret) {
		dev_err(ipts->dev, "Failed to request flush: %d\n", ret);
		return ret;
	}

	return ipts_receiver_finish(ipts);
}

static int ipts_receiver_poll_loop(struct ipts_thread *thread)
{
	int ret = 0;
	u32 buffer = 0;

	u32 doorbell = 0;
	u32 lastdb = 0;

	struct ipts_context *ipts = NULL;
	time64_t last = ktime_get_seconds();

	if (!thread)
		return -EFAULT;

	ipts = thread->data;

	if (!ipts)
		return -EFAULT;

	dev_info(ipts->dev, "IPTS running in poll mode\n");

	while (!ipts_thread_should_stop(thread)) {
		doorbell = ipts_receiver_current_doorbell(ipts);
		lastdb = ipts_receiver_first_new(doorbell, lastdb);

		/*
		 * After filling up one of the data buffers, IPTS will increment
		 * the doorbell. The value of the doorbell stands for the *next*
		 * buffer that IPTS is going to fill.
		 */
		while (lastdb != doorbell && !ipts_thread_should_stop(thread)) {
			buffer = lastdb % IPTS_BUFFERS;

			ret = ipts_hid_input_data(ipts, buffer);
			if (ret)
				dev_err(ipts->dev, "Failed to process buffer: %d\n", ret);

			ret = ipts_control_refill_buffer(ipts, buffer);
			if (ret)
				dev_err(ipts->dev, "Failed to send feedback: %d\n", ret);

			last = ktime_get_seconds();
			lastdb++;
		}

		if (ipts_thread_should_stop(thread))
			break;

		ipts_receiver_backoff(last, 5);
	}

	ret = ipts_control_request_flush(ipts);
	if (ret) {
		dev_err(ipts->dev, "Failed to request flush: %d\n", ret);
		return ret;
	}

	ipts_receiver_return_buffers(ipts, lastdb);

	return ipts_receiver_finish(ipts);
}

int ipts_receiver_start(struct ipts_context *ipts)
{
	int ret = 0;

	if (!ipts)
		return -EFAULT;

	if (ipts->mode == IPTS_MODE_EVENT) {
		ret = ipts_thread_start(&ipts->receiver_loop, ipts_receiver_event_loop, ipts,
					"ipts_event");
	} else if (ipts->mode == IPTS_MODE_POLL) {
		ret = ipts_thread_start(&ipts->receiver_loop, ipts_receiver_poll_loop, ipts,
					"ipts_poll");
	} else {
		ret = -EINVAL;
	}

	if (ret) {
		dev_err(ipts->dev, "Failed to start receiver loop: %d\n", ret);
		return ret;
	}

	/*
	 * The receiver thread uses the context until it stops: hold a reference for its whole run.
	 */
	ipts_context_get(ipts);

	return 0;
}

int ipts_receiver_stop(struct ipts_context *ipts)
{
	int ret = 0;

	if (!ipts)
		return -EFAULT;

	/*
	 * A start that failed early never started the thread: there is no reference to drop,
	 * and the exit code of an earlier thread must not be reported again.
	 */
	if (!ipts->receiver_loop.thread) {
		ipts->receiver_loop.exit_code = 0;
		return 0;
	}

	ret = ipts_thread_stop(&ipts->receiver_loop, IPTS_RECEIVER_STOP_TIMEOUT_MS);
	if (ret == -ETIMEDOUT) {
		/*
		 * Still running: the thread keeps its reference, and everything it uses.
		 */
		dev_err(ipts->dev, "Failed to stop receiver loop: %d\n", ret);
		return ret;
	}

	/*
	 * The thread is gone (it returned or died), so drop its reference.
	 */
	ipts_context_put(ipts);

	if (ret) {
		dev_err(ipts->dev, "Failed to stop receiver loop: %d\n", ret);
		return ret;
	}

	return 0;
}
