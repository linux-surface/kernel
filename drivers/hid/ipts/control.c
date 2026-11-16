// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020-2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#include <linux/delay.h>
#include <linux/dev_printk.h>
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>

#include "cmd.h"
#include "context.h"
#include "control.h"
#include "desc.h"
#include "hid.h"
#include "receiver.h"
#include "resources.h"
#include "spec-data.h"
#include "spec-device.h"

#define IPTS_RESTART_DELAY_MS	  2000
#define IPTS_RESTART_MAX_ATTEMPTS 5

static int ipts_control_get_device_info(struct ipts_context *ipts, struct ipts_device_info *info)
{
	int ret = 0;
	struct ipts_response rsp = { 0 };

	if (!ipts)
		return -EFAULT;

	if (!info)
		return -EFAULT;

	ret = ipts_cmd_send(ipts, IPTS_CMD_GET_DEVICE_INFO, NULL, 0);
	if (ret) {
		dev_err(ipts->dev, "GET_DEVICE_INFO: send failed: %d\n", ret);
		return ret;
	}

	ret = ipts_cmd_recv(ipts, IPTS_CMD_GET_DEVICE_INFO, &rsp);
	if (ret) {
		dev_err(ipts->dev, "GET_DEVICE_INFO: recv failed: %d\n", ret);
		return ret;
	}

	if (rsp.status != IPTS_STATUS_SUCCESS) {
		dev_err(ipts->dev, "GET_DEVICE_INFO: cmd failed: %d\n", rsp.status);
		return -EBADR;
	}

	memcpy(info, rsp.payload, sizeof(*info));
	return 0;
}

static int ipts_control_set_mode(struct ipts_context *ipts, enum ipts_mode mode)
{
	int ret = 0;
	struct ipts_set_mode cmd = { 0 };
	struct ipts_response rsp = { 0 };

	if (!ipts)
		return -EFAULT;

	cmd.mode = mode;

	ret = ipts_cmd_send(ipts, IPTS_CMD_SET_MODE, &cmd, sizeof(cmd));
	if (ret) {
		dev_err(ipts->dev, "SET_MODE: send failed: %d\n", ret);
		return ret;
	}

	ret = ipts_cmd_recv(ipts, IPTS_CMD_SET_MODE, &rsp);
	if (ret) {
		dev_err(ipts->dev, "SET_MODE: recv failed: %d\n", ret);
		return ret;
	}

	if (rsp.status != IPTS_STATUS_SUCCESS) {
		dev_err(ipts->dev, "SET_MODE: cmd failed: %d\n", rsp.status);
		return -EBADR;
	}

	return 0;
}

static int ipts_control_set_mem_window(struct ipts_context *ipts, struct ipts_resources *res)
{
	int i = 0;
	int ret = 0;
	struct ipts_mem_window cmd = { 0 };
	struct ipts_response rsp = { 0 };

	if (!ipts)
		return -EFAULT;

	if (!res)
		return -EFAULT;

	for (i = 0; i < IPTS_BUFFERS; i++) {
		cmd.data_addr_lower[i] = lower_32_bits(res->data[i].dma_address);
		cmd.data_addr_upper[i] = upper_32_bits(res->data[i].dma_address);
		cmd.feedback_addr_lower[i] = lower_32_bits(res->feedback[i].dma_address);
		cmd.feedback_addr_upper[i] = upper_32_bits(res->feedback[i].dma_address);
	}

	cmd.workqueue_addr_lower = lower_32_bits(res->workqueue.dma_address);
	cmd.workqueue_addr_upper = upper_32_bits(res->workqueue.dma_address);

	cmd.doorbell_addr_lower = lower_32_bits(res->doorbell.dma_address);
	cmd.doorbell_addr_upper = upper_32_bits(res->doorbell.dma_address);

	cmd.hid2me_addr_lower = lower_32_bits(res->hid2me.dma_address);
	cmd.hid2me_addr_upper = upper_32_bits(res->hid2me.dma_address);

	cmd.workqueue_size = IPTS_WORKQUEUE_SIZE;
	cmd.workqueue_item_size = IPTS_WORKQUEUE_ITEM_SIZE;

	ret = ipts_cmd_send(ipts, IPTS_CMD_SET_MEM_WINDOW, &cmd, sizeof(cmd));
	if (ret) {
		dev_err(ipts->dev, "SET_MEM_WINDOW: send failed: %d\n", ret);
		return ret;
	}

	ret = ipts_cmd_recv(ipts, IPTS_CMD_SET_MEM_WINDOW, &rsp);
	if (ret) {
		dev_err(ipts->dev, "SET_MEM_WINDOW: recv failed: %d\n", ret);
		return ret;
	}

	if (rsp.status != IPTS_STATUS_SUCCESS) {
		dev_err(ipts->dev, "SET_MEM_WINDOW: cmd failed: %d\n", rsp.status);
		return -EBADR;
	}

	return 0;
}

static int ipts_control_get_descriptor(struct ipts_context *ipts)
{
	int ret = 0;
	struct ipts_data_header *header = NULL;
	struct ipts_get_descriptor cmd = { 0 };
	struct ipts_response rsp = { 0 };

	if (!ipts)
		return -EFAULT;

	if (!ipts->resources.descriptor.address)
		return -EFAULT;

	memset(ipts->resources.descriptor.address, 0, ipts->resources.descriptor.size);

	cmd.addr_lower = lower_32_bits(ipts->resources.descriptor.dma_address);
	cmd.addr_upper = upper_32_bits(ipts->resources.descriptor.dma_address);
	cmd.magic = 8;

	ret = ipts_cmd_send(ipts, IPTS_CMD_GET_DESCRIPTOR, &cmd, sizeof(cmd));
	if (ret) {
		dev_err(ipts->dev, "GET_DESCRIPTOR: send failed: %d\n", ret);
		return ret;
	}

	ret = ipts_cmd_recv(ipts, IPTS_CMD_GET_DESCRIPTOR, &rsp);
	if (ret) {
		dev_err(ipts->dev, "GET_DESCRIPTOR: recv failed: %d\n", ret);
		return ret;
	}

	if (rsp.status != IPTS_STATUS_SUCCESS) {
		dev_err(ipts->dev, "GET_DESCRIPTOR: cmd failed: %d\n", rsp.status);
		return -EBADR;
	}

	header = (struct ipts_data_header *)ipts->resources.descriptor.address;

	if (header->type == IPTS_DATA_TYPE_DESCRIPTOR) {
		ipts->descriptor.address = &header->data[8];
		ipts->descriptor.size = header->size - 8;

		return 0;
	}

	return -ENODATA;
}

int ipts_control_request_flush(struct ipts_context *ipts)
{
	int ret = 0;
	struct ipts_quiesce_io cmd = { 0 };

	if (!ipts)
		return -EFAULT;

	ret = ipts_cmd_send(ipts, IPTS_CMD_QUIESCE_IO, &cmd, sizeof(cmd));
	if (ret)
		dev_err(ipts->dev, "QUIESCE_IO: send failed: %d\n", ret);

	return ret;
}

int ipts_control_wait_flush(struct ipts_context *ipts)
{
	int ret = 0;
	struct ipts_response rsp = { 0 };

	if (!ipts)
		return -EFAULT;

	ret = ipts_cmd_recv(ipts, IPTS_CMD_QUIESCE_IO, &rsp);
	if (ret) {
		dev_err(ipts->dev, "QUIESCE_IO: recv failed: %d\n", ret);
		return ret;
	}

	if (rsp.status == IPTS_STATUS_TIMEOUT)
		return -EAGAIN;

	if (rsp.status != IPTS_STATUS_SUCCESS) {
		dev_err(ipts->dev, "QUIESCE_IO: cmd failed: %d\n", rsp.status);
		return -EBADR;
	}

	return 0;
}

int ipts_control_request_data(struct ipts_context *ipts)
{
	int ret = 0;

	if (!ipts)
		return -EFAULT;

	ret = ipts_cmd_send(ipts, IPTS_CMD_READY_FOR_DATA, NULL, 0);
	if (ret)
		dev_err(ipts->dev, "READY_FOR_DATA: send failed: %d\n", ret);

	return ret;
}

int ipts_control_wait_data(struct ipts_context *ipts, bool shutdown)
{
	int ret = 0;
	struct ipts_response rsp = { 0 };

	if (!ipts)
		return -EFAULT;

	if (!shutdown)
		ret = ipts_cmd_recv_timeout(ipts, IPTS_CMD_READY_FOR_DATA, &rsp, 0);
	else
		ret = ipts_cmd_recv(ipts, IPTS_CMD_READY_FOR_DATA, &rsp);

	if (ret) {
		if (ret != -EAGAIN)
			dev_err(ipts->dev, "READY_FOR_DATA: recv failed: %d\n", ret);

		return ret;
	}

	/*
	 * During shutdown, it is possible that the sensor has already been disabled.
	 */
	if (rsp.status == IPTS_STATUS_SENSOR_DISABLED)
		return 0;

	if (rsp.status == IPTS_STATUS_TIMEOUT)
		return -EAGAIN;

	if (rsp.status != IPTS_STATUS_SUCCESS) {
		dev_err(ipts->dev, "READY_FOR_DATA: cmd failed: %d\n", rsp.status);
		return -EBADR;
	}

	return 0;
}

static int ipts_control_send_feedback_locked(struct ipts_context *ipts, u32 buffer)
{
	int ret = 0;
	int late = 0;
	long left = 0;
	u32 answered = 0;
	unsigned long end = 0;
	struct ipts_feedback cmd = { 0 };
	struct ipts_response rsp = { 0 };

	lockdep_assert_held(&ipts->feedback_lock);

	/*
	 * No other FEEDBACK is in flight while the lock is held, so a FEEDBACK reply that is
	 * already queued answers one whose sender gave up waiting. Drop it, or this send would
	 * take it as its own.
	 */
	while (!ipts_cmd_recv_timeout(ipts, IPTS_CMD_FEEDBACK, &rsp, 0))
		late++;

	if (late)
		dev_warn(ipts->dev, "FEEDBACK: dropped %d late replies\n", late);

	cmd.buffer = buffer;

	ret = ipts_cmd_send(ipts, IPTS_CMD_FEEDBACK, &cmd, sizeof(cmd));
	if (ret) {
		dev_err(ipts->dev, "FEEDBACK: send failed: %d\n", ret);
		return ret;
	}

	/*
	 * The first word of a FEEDBACK reply's payload echoes the buffer index of the command it
	 * answers. A reply for another buffer answers a sender that gave up after the drop above
	 * ran: drop it too and keep waiting for ours, within the usual time limit. Two hid2me
	 * replies look alike, but the lock allows one hid2me FEEDBACK at a time.
	 */
	end = jiffies + msecs_to_jiffies(IPTS_CMD_DEFAULT_TIMEOUT);

	do {
		left = (long)(end - jiffies);

		ret = ipts_cmd_recv_timeout(ipts, IPTS_CMD_FEEDBACK, &rsp,
					    left > 0 ? jiffies_to_msecs(left) : 0);
		if (ret) {
			dev_err(ipts->dev, "FEEDBACK: recv failed: %d\n", ret);
			return ret;
		}

		answered = get_unaligned_le32(rsp.payload);
		if (answered != buffer)
			dev_warn(ipts->dev, "FEEDBACK: dropped a reply for buffer %u, waiting for %u\n",
				 answered, buffer);
	} while (answered != buffer);

	/*
	 * We don't know what feedback data looks like so we are sending zeros.
	 * See also ipts_control_refill_buffer.
	 */
	if (rsp.status == IPTS_STATUS_INVALID_PARAMS)
		return 0;

	if (rsp.status != IPTS_STATUS_SUCCESS) {
		dev_err(ipts->dev, "FEEDBACK: cmd failed: %d\n", rsp.status);
		return -EBADR;
	}

	return 0;
}

/*
 * The receiver loop and HID feature requests both send FEEDBACK, and a reply is matched to
 * its sender by the command code only. With several FEEDBACKs in flight, a sender can take
 * the reply to another one and return while its own command is still pending. The device
 * then stays a reply behind, holding its newest reply until the next command, and never
 * confirms a QUIESCE_IO sent in that state. One FEEDBACK at a time, dropping a reply that
 * arrived after its sender gave up, and taking only the reply that names the sender's buffer
 * keep each reply with its sender. The lock is held for a bounded time: the send and the
 * reply wait are both bounded.
 */
int ipts_control_send_feedback(struct ipts_context *ipts, u32 buffer)
{
	int ret = 0;

	if (!ipts)
		return -EFAULT;

	mutex_lock(&ipts->feedback_lock);
	ret = ipts_control_send_feedback_locked(ipts, buffer);
	mutex_unlock(&ipts->feedback_lock);

	return ret;
}

int ipts_control_hid2me_feedback(struct ipts_context *ipts, enum ipts_feedback_cmd_type cmd,
				 enum ipts_feedback_data_type type, void *data, size_t size)
{
	int ret = 0;
	struct ipts_feedback_header *header = NULL;

	if (!ipts)
		return -EFAULT;

	if (!ipts->resources.hid2me.address)
		return -EFAULT;

	/*
	 * There is one hid2me buffer. Fill it under the lock, which is held until the device
	 * answered this FEEDBACK, so a second request cannot overwrite it before then. (That the
	 * device is done reading the buffer once it answered is assumed, not known.)
	 * GET_FEATURE waits for its report only after this returns, with the lock released,
	 * because the receiver loop needs the lock to give back the buffer the report is in.
	 */
	mutex_lock(&ipts->feedback_lock);

	memset(ipts->resources.hid2me.address, 0, ipts->resources.hid2me.size);
	header = (struct ipts_feedback_header *)ipts->resources.hid2me.address;

	header->cmd_type = cmd;
	header->data_type = type;
	header->size = size;
	header->buffer = IPTS_HID2ME_BUFFER;

	if (size + sizeof(*header) > ipts->resources.hid2me.size) {
		ret = -EINVAL;
		goto out;
	}

	if (data && size > 0)
		memcpy(header->payload, data, size);

	ret = ipts_control_send_feedback_locked(ipts, IPTS_HID2ME_BUFFER);

out:
	mutex_unlock(&ipts->feedback_lock);
	return ret;
}

/*
 * The device was never told to stop, or never confirmed it, so it may still write to its
 * DMA buffers. They are never freed; the next start allocates new ones. The report buffer
 * is driver memory only and is freed.
 */
static void ipts_control_leak_buffers(struct ipts_context *ipts)
{
	dev_warn(ipts->dev, "Device stop not confirmed, leaking its DMA buffers\n");

	kfree(ipts->resources.report.address);
	memset(&ipts->resources, 0, sizeof(ipts->resources));
	ipts->buffers_unconfirmed = false;
}

int ipts_control_start(struct ipts_context *ipts)
{
	int ret = 0;
	size_t stale = 0;
	struct ipts_device_info info = { 0 };

	if (!ipts)
		return -EFAULT;

	dev_info(ipts->dev, "Starting IPTS\n");

	/*
	 * Responses to commands that were interrupted while sending (or that timed out) can
	 * still arrive later. Drop them, so that they are not mistaken for responses to the
	 * commands sent below.
	 */
	stale = ipts_mei_flush(&ipts->mei);
	if (stale)
		dev_dbg(ipts->dev, "Dropped %zu stale responses\n", stale);

	ret = ipts_control_get_device_info(ipts, &info);
	if (ret) {
		dev_err(ipts->dev, "Failed to get device info: %d\n", ret);
		return ret;
	}

	ipts->info = info;

	ret = ipts_resources_init(&ipts->resources, ipts->dev, info.data_size, info.feedback_size);
	if (ret) {
		dev_err(ipts->dev, "Failed to allocate buffers: %d", ret);
		return ret;
	}

	dev_info(ipts->dev, "IPTS EDS Version: %d\n", info.intf_eds);

	/*
	 * Handle newer devices
	 */
	if (info.intf_eds > 1) {
		/*
		 * Fetching the descriptor will only work on newer devices.
		 * For older devices, a fallback descriptor will be used.
		 */
		ret = ipts_control_get_descriptor(ipts);
		if (ret) {
			dev_err(ipts->dev, "Failed to fetch HID descriptor: %d\n", ret);

			/*
			 * Unless the device replied, it may still write the descriptor into its
			 * buffer.
			 */
			if (ret == -EBADR || ret == -ENODATA)
				goto err_free_resources;

			goto err_leak_resources;
		}

		/*
		 * Newer devices can be directly initialized in polling mode.
		 */
		ipts->mode = IPTS_MODE_POLL;
	}

	ret = ipts_control_set_mode(ipts, ipts->mode);
	if (ret) {
		dev_err(ipts->dev, "Failed to set mode: %d\n", ret);
		goto err_free_resources;
	}

	ret = ipts_control_set_mem_window(ipts, &ipts->resources);
	if (ret) {
		dev_err(ipts->dev, "Failed to set memory window: %d\n", ret);
		goto err_leak_resources;
	}

	ret = ipts_receiver_start(ipts);
	if (ret) {
		dev_err(ipts->dev, "Failed to start receiver: %d\n", ret);
		goto err_leak_resources;
	}

	ret = ipts_control_request_data(ipts);
	if (ret) {
		dev_err(ipts->dev, "Failed to request data: %d\n", ret);
		goto err_stop;
	}

	ipts_hid_enable(ipts);

	ret = ipts_hid_init(ipts, info);
	if (ret) {
		dev_err(ipts->dev, "Failed to initialize HID device: %d\n", ret);
		goto err_stop;
	}

	return 0;

err_stop:
	/*
	 * The receiver is running: stop it through the normal stop path, which keeps whatever
	 * a receiver thread that does not stop can still use.
	 */
	ipts_control_stop(ipts);
	return ret;

err_leak_resources:
	/*
	 * The device may already have been given these buffers and was never told to stop.
	 */
	ipts_control_leak_buffers(ipts);
	return ret;

err_free_resources:
	ipts_resources_free(&ipts->resources);
	return ret;
}

/*
 * Returned by _ipts_control_stop() when the receiver thread is gone, but the device did not
 * confirm its stop, or a HID request overlapped it: its DMA buffers were leaked, and it must
 * not be started again.
 */
#define IPTS_STOP_LEAKED 1

static int _ipts_control_stop(struct ipts_context *ipts)
{
	int ret = 0;
	bool busy = false;

	if (!ipts)
		return -EFAULT;

	dev_info(ipts->dev, "Stopping IPTS\n");

	busy = ipts_hid_quiesce(ipts, IPTS_HID_QUIESCE_TIMEOUT_MS) == -ETIMEDOUT;

	/*
	 * A HID callback that outlives the wait may send the device a command after it confirmed
	 * the stop below, and the device may answer by writing to the buffers again. They are
	 * leaked then, by this stop or, if it keeps everything, by a later one.
	 */
	if (busy)
		ipts->buffers_unconfirmed = true;

	/*
	 * The receiver is asked to stop in any case. A HID callback that was only slow may
	 * return meanwhile; once the count is zero, no new one starts, since HID input is off.
	 */
	ret = ipts_receiver_stop(ipts);

	if (busy && atomic_read(&ipts->hid_users) == 0)
		busy = false;

	if (busy) {
		/*
		 * A HID request, or the receiver's HID input, is stuck in driver code, most
		 * likely in a task that died inside it. It can still touch the buffers, and
		 * destroying the HID device could block forever on HID core locks that task
		 * holds, so nothing is freed. A later stop must not free the buffers either,
		 * although it finds no thread anymore.
		 */
		dev_err(ipts->dev, "A HID request did not return (%d still running)\n",
			atomic_read(&ipts->hid_users));
		return -EBUSY;
	}

	if (ret == -ETIMEDOUT) {
		/*
		 * The thread is still running and can still touch the buffers, so they are
		 * kept. It can no longer reach the HID device: its HID input is counted, and
		 * nothing counted is running anymore.
		 */
		dev_err(ipts->dev, "Receiver thread did not stop\n");
		return ret;
	}

	if (ret) {
		dev_err(ipts->dev, "Receiver thread died without stopping the device: %d\n", ret);
		ipts_control_leak_buffers(ipts);
		return IPTS_STOP_LEAKED;
	}

	if (ipts->receiver_loop.exit_code) {
		dev_err(ipts->dev, "Failed to stop the device: %d\n",
			ipts->receiver_loop.exit_code);
		ipts_control_leak_buffers(ipts);
		return IPTS_STOP_LEAKED;
	}

	if (ipts->buffers_unconfirmed) {
		dev_err(ipts->dev, "Device may still use its buffers, leaking them\n");
		ipts_control_leak_buffers(ipts);
		return IPTS_STOP_LEAKED;
	}

	ret = ipts_resources_free(&ipts->resources);
	if (ret)
		dev_err(ipts->dev, "Failed to free resources: %d\n", ret);

	return 0;
}

int ipts_control_stop(struct ipts_context *ipts)
{
	int ret = 0;
	int err = 0;

	if (!ipts)
		return -EFAULT;

	/*
	 * The HID device must be gone before the module can unload, or opening its hidraw node
	 * later runs freed module code. Once no HID callback and no HID input of the receiver
	 * runs, and none can start, it is destroyed, even when the receiver thread did not stop.
	 * It is kept only while a HID callback is stuck.
	 */
	ret = _ipts_control_stop(ipts);
	if (ret == -EBUSY)
		return ret;

	err = ipts_hid_free(ipts);
	if (err)
		dev_err(ipts->dev, "Failed to free HID device: %d\n", err);

	/*
	 * Leaked buffers are not an error for the callers.
	 */
	if (ret == IPTS_STOP_LEAKED)
		return 0;

	return ret;
}

static void ipts_control_restart_work(struct work_struct *work)
{
	int ret = 0;
	struct ipts_context *ipts =
		container_of(to_delayed_work(work), struct ipts_context, restart_work);

	mutex_lock(&ipts->ctl_lock);

	if (READ_ONCE(ipts->removing))
		goto out;

	/*
	 * Also on a retry, although the failed start left the device stopped: on a stopped device
	 * this does nothing, but if the start failed after it started the receiver and that did
	 * not stop, or the device did not confirm its stop, it keeps the device from being
	 * started again, as for any other restart.
	 */
	ret = _ipts_control_stop(ipts);
	if (ret == IPTS_STOP_LEAKED) {
		/*
		 * The device did not confirm its stop, or a HID request may have sent it a
		 * command after it did. Starting it again can leave its firmware unresponsive
		 * until the next boot.
		 */
		dev_err(ipts->dev, "Device may not have stopped, not restarting IPTS\n");
		goto out;
	}

	if (ret) {
		dev_err(ipts->dev, "Failed to stop IPTS for a restart: %d\n", ret);
		goto out;
	}

	if (ipts->restart_attempts) {
		dev_info(ipts->dev, "Restarting IPTS after a failed mode switch\n");

		/*
		 * After a timeout, every response from the ME can arrive only when the next
		 * command is sent, which makes all further commands time out as well. Waiting
		 * doesn't help, but reconnecting does.
		 */
		ret = ipts_mei_reconnect(&ipts->mei);
		if (ret) {
			dev_err(ipts->dev, "Failed to reconnect to the ME: %d\n", ret);
			goto failed;
		}
	}

	/*
	 * Wait a second to give the sensor time to fully shut down.
	 */
	msleep(1000);

	/*
	 * A remove that started meanwhile waits for this, and stops the device anyway.
	 */
	if (READ_ONCE(ipts->removing))
		goto out;

	ret = ipts_control_start(ipts);
	if (!ret) {
		ipts->restart_attempts = 0;
		goto out;
	}

	dev_err(ipts->dev, "Failed to restart IPTS: %d\n", ret);

failed:
	if (++ipts->restart_attempts >= IPTS_RESTART_MAX_ATTEMPTS) {
		dev_err(ipts->dev, "Giving up restarting IPTS: %d\n", ret);
		ipts->restart_attempts = 0;
		goto out;
	}

	if (READ_ONCE(ipts->removing))
		goto out;

	/*
	 * The device is stopped, and the HID device is inactive, so userspace cannot retry.
	 * Restart the device in the previous mode, which works without iptsd, and iptsd can
	 * switch modes again once it is restarted. The retry holds its own reference.
	 */
	ipts->mode = ipts->restart_old_mode;

	ipts_context_get(ipts);
	if (!schedule_delayed_work(&ipts->restart_work, msecs_to_jiffies(IPTS_RESTART_DELAY_MS)))
		ipts_context_put(ipts);

out:
	mutex_unlock(&ipts->ctl_lock);

	/*
	 * Drop the reference that ipts_control_restart() took for this run.
	 */
	ipts_context_put(ipts);
}

void ipts_control_init(struct ipts_context *ipts)
{
	mutex_init(&ipts->ctl_lock);
	INIT_DELAYED_WORK(&ipts->restart_work, ipts_control_restart_work);
	ipts->restart_attempts = 0;
	ipts->removing = false;
}

int ipts_control_restart(struct ipts_context *ipts)
{
	if (!ipts)
		return -EFAULT;

	/*
	 * Called from a HID callback, which the stop has to wait for, so the restart itself
	 * runs from a work item.
	 */
	if (READ_ONCE(ipts->removing))
		return -ENODEV;

	/*
	 * A queued restart holds a reference until it ran or was cancelled. If one is queued
	 * already, it holds its own.
	 */
	ipts_context_get(ipts);
	if (!schedule_delayed_work(&ipts->restart_work, 0))
		ipts_context_put(ipts);

	return 0;
}

void ipts_control_cancel_restart(struct ipts_context *ipts)
{
	/*
	 * Never waits: a restart that is running holds ctl_lock, which remove waits for with a
	 * bound. A queued one that is cancelled drops its reference here.
	 */
	if (cancel_delayed_work(&ipts->restart_work))
		ipts_context_put(ipts);
}
