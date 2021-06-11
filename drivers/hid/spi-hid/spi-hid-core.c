/*
 * HID over SPI protocol implementation
 * spi-hid-core.h
 *
 * Copyright (c) 2020 Microsoft Corporation
 *
 * This code is partly based on "HID over I2C protocol implementation:
 *
 *  Copyright (c) 2012 Benjamin Tissoires <benjamin.tissoires@gmail.com>
 *  Copyright (c) 2012 Ecole Nationale de l'Aviation Civile, France
 *  Copyright (c) 2012 Red Hat, Inc
 *
 *  which in turn is partly based on "USB HID support for Linux":
 *
 *  Copyright (c) 1999 Andreas Gal
 *  Copyright (c) 2000-2005 Vojtech Pavlik <vojtech@suse.cz>
 *  Copyright (c) 2005 Michael Haboustak <mike-@cinci.rr.com> for Concept2, Inc
 *  Copyright (c) 2007-2008 Oliver Neukum
 *  Copyright (c) 2006-2010 Jiri Kosina
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/spi/spi.h>
#include <linux/interrupt.h>
#include <linux/input.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/pm.h>
#include <linux/pm_runtime.h>
#include <linux/pm_wakeirq.h>
#include <linux/device.h>
#include <linux/wait.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/hid.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/regulator/consumer.h>
#include <linux/workqueue.h>
#include <linux/dma-mapping.h>

#include "spi-hid-dev.h"
#include "spi-hid-protocol.h"
#include "spi-hid-power.h"
#include "../hid-ids.h"

#define SPI_HID_RESPONSE_STATUS_OK      0
#define SPI_HID_RESPONSE_STATUS_PENDING 1
#define SPI_HID_RESPONSE_STATUS_TIMEOUT 2

#define SPI_HID_MAX_RESET_ATTEMPTS 3

// Time to keep system awake on wakeup event for processing in ms
#define SPI_HID_DEV_WAKEUP_DELAY 3000

struct spi_hid {
	struct spi_device	*spi;
	struct hid_device	*hid;
	struct spi_hid_dev dev;
	struct spi_hid_power pwr;

	u32 device_descriptor_register;
	u32 sleep_timeout_ms;

	u8 attempts;

	struct work_struct dev_error_work;
	struct work_struct dev_reset_work;
	struct work_struct dev_ready_work;
	struct work_struct input_report_work;
	struct work_struct response_work;

	struct mutex ctrl_lock;
	struct mutex intr_lock;

	struct {
		wait_queue_head_t wait;
		atomic_t status;
		u8 *data;
		u16 len;
	} response;
};

static void spi_hid_callback_dev_event(void *context, int event)
{
	struct spi_hid *shid = (struct spi_hid *)context;

	switch (event) {
		case SPI_HID_DEV_EVENT_ERROR:
			schedule_work(&shid->dev_error_work);
			break;
		case SPI_HID_DEV_EVENT_RESET:
			schedule_work(&shid->dev_reset_work);
			break;
		case SPI_HID_DEV_EVENT_READY:
			schedule_work(&shid->dev_ready_work);
			break;
		case SPI_HID_DEV_EVENT_INPUT_REPORT:
			// input reports are high prio and driver wq may be blocking
			queue_work(system_highpri_wq, &shid->input_report_work);
			return;
		case SPI_HID_DEV_EVENT_RESPONSE:
			// we use system_wq since the driver wq is blocking waiting for this resp
			schedule_work(&shid->response_work);
			break;
		case SPI_HID_DEV_EVENT_WAKEUP:
			// runtime_get will wake the device, at some point command to wake the
			// device will have been sent and handled which is _put is called
			pm_runtime_get(&shid->spi->dev);
			pm_wakeup_dev_event(&shid->spi->dev, SPI_HID_DEV_WAKEUP_DELAY, true);
			break;
		default:
			break;
	}
}

/* Middle level helper functions */
static int spi_hid_async_request(struct spi_hid *shid, u16 output_register,
		struct spi_hid_output_report *report)
{
	if (atomic_cmpxchg(
		&shid->response.status,
		SPI_HID_RESPONSE_STATUS_OK,
		SPI_HID_RESPONSE_STATUS_PENDING
	) == SPI_HID_RESPONSE_STATUS_OK) {
		return spi_hid_dev_output_report(&shid->dev, output_register, report);
	} else {
		dev_err(&shid->spi->dev, "%s called while request in progress\n", __func__);
		return -EINPROGRESS;
	}
}

static void spi_hid_async_response(struct spi_hid *shid, int status,
		u8 *response, u16 response_len)
{
	if (atomic_cmpxchg(
		&shid->response.status,
		SPI_HID_RESPONSE_STATUS_PENDING,
		status
	) == SPI_HID_RESPONSE_STATUS_PENDING) {
		shid->response.data = response;
		shid->response.len = response_len;
		wake_up(&shid->response.wait);
	} else {
		atomic_cmpxchg(
			&shid->response.status,
			SPI_HID_RESPONSE_STATUS_TIMEOUT,
			SPI_HID_RESPONSE_STATUS_OK
		);
	}
}

static int spi_hid_async_response_await(struct spi_hid *shid)
{
	int status;
	if (wait_event_timeout(
		shid->response.wait,
		atomic_read(&shid->response.status) != SPI_HID_RESPONSE_STATUS_PENDING,
		msecs_to_jiffies(1000)
	)) {
		return atomic_xchg(&shid->response.status, SPI_HID_RESPONSE_STATUS_OK);
	} else { // response may have written status here, swap in timeout
		status = atomic_xchg(
			&shid->response.status,
			SPI_HID_RESPONSE_STATUS_TIMEOUT
		); // response may clear TIMEOUT with OK here, doesn't matter
		if (status != SPI_HID_RESPONSE_STATUS_PENDING) {
			// response did infact write status before us writing timeout, write OK
			atomic_set(&shid->response.status, SPI_HID_RESPONSE_STATUS_OK);
			return status;
		}
		dev_err(&shid->spi->dev, "%s response timed out\n", __func__);
		return -ETIMEDOUT;
	}
}

static int spi_hid_sync_request(struct spi_hid *shid, u16 output_register,
		struct spi_hid_output_report *report)
{
	return spi_hid_async_request(shid, output_register, report) ?:
			spi_hid_async_response_await(shid);
}

static int spi_hid_get_request(struct spi_hid *shid, u8 content_id)
{
	struct spi_hid_output_report report = {
		.content_type = SPI_HID_CONTENT_TYPE_GET_FEATURE,
		.content_length = 0,
		.content_id = content_id,
		.content = NULL,
	};
	return spi_hid_sync_request(shid, shid->dev.desc.output_register, &report);
}

static int spi_hid_set_request(struct spi_hid *shid,
		u8 *arg_buf, u16 arg_len, u8 content_id)
{
	struct spi_hid_output_report report = {
		.content_type = SPI_HID_CONTENT_TYPE_SET_FEATURE,
		.content_length = arg_len,
		.content_id = content_id,
		.content = arg_buf,
	};
	return spi_hid_dev_output_report(&shid->dev,
			shid->dev.desc.output_register, &report);
}

static int spi_hid_command(struct spi_hid *shid, u8 opcode,
		u8 *arg_buf, u16 arg_len)
{
	struct spi_hid_output_report report = {
		.content_type = SPI_HID_CONTENT_TYPE_COMMAND,
		.content_length = arg_len,
		.content_id = opcode,
		.content = arg_buf,
	};
	return spi_hid_dev_output_report(&shid->dev,
			shid->dev.desc.command_register, &report);
}

static int spi_hid_command_acked(struct spi_hid *shid, u8 opcode,
		u8 *arg_buf, u16 arg_len)
{
	int ret;
	struct spi_hid_output_report report = {
		.content_type = SPI_HID_CONTENT_TYPE_COMMAND,
		.content_length = arg_len,
		.content_id = opcode,
		.content = arg_buf,
	};
	ret = spi_hid_sync_request(shid, shid->dev.desc.command_register, &report);
	if (ret || shid->response.len < 1 || shid->response.data[0] != arg_buf[0]) {
		dev_err(&shid->spi->dev,
				"%s power command not acked by device, \
				ret: %d, len: %d, arg: 0x%x ack: 0x%x\n",
				ret, shid->response.len, shid->response.data[0], arg_buf[0], __func__);
		ret = -1;
	}
	return ret;
}

static int spi_hid_descriptor_request(struct spi_hid *shid, u16 output_register)
{
	struct spi_hid_output_report report = {
		.content_type = SPI_HID_CONTENT_TYPE_COMMAND,
		.content_length = 0,
		.content_id = 0,
		.content = 0,
	};
	return spi_hid_sync_request(shid, output_register, &report);
}

static int spi_hid_power_mode(struct spi_hid *shid, u8 mode)
{
	int ret;

	switch (shid->dev.desc.device_power_support) {
		case SPI_HID_POWER_SUPPORT_RESP:
			if (mode == SPI_HID_POWER_MODE_ACTIVE)
				return spi_hid_command_acked(shid, SPI_HID_COMMAND_SET_POWER,
					&mode, sizeof(mode));
			// fallthrough
		case SPI_HID_POWER_SUPPORT_NO_RESP:
			ret = spi_hid_command(shid, SPI_HID_COMMAND_SET_POWER,
					&mode, sizeof(mode));
			msleep(shid->dev.desc.power_response_delay);
			return ret;
		case SPI_HID_POWER_SUPPORT_NONE:
		default:
			// Don't print error message if device do not support a valid power mode
			return -EINVAL;
	}
}

/* hid_ll_driver interface functions */

static int spi_hid_ll_start(struct hid_device *hid)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);

	if (HID_MIN_BUFFER_SIZE > shid->dev.desc.max_input_length) {
		dev_err(&shid->spi->dev, "HID_MIN_BUFFER_SIZE > max_input_length (%d)\n",
				shid->dev.desc.max_input_length);
		return -1;
	}

	return 0;
}

static void spi_hid_ll_stop(struct hid_device *hid)
{
	hid->claimed = 0;
}

static int spi_hid_ll_open(struct hid_device *hid)
{
	return 0;
}

static void spi_hid_ll_close(struct hid_device *hid)
{
	return;
}

static int spi_hid_ll_power(struct hid_device *hid, int level)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	int ret = 0;
	mutex_lock(&shid->ctrl_lock);
	if (shid->hid) {
		pm_runtime_get(&shid->spi->dev);
		pm_runtime_mark_last_busy(&shid->spi->dev);
		pm_runtime_put(&shid->spi->dev);
	} else {
		ret = -ENODEV;
		// Don't print error message as this case is expected and non-critical
	}
	mutex_unlock(&shid->ctrl_lock);
	return ret;
}

static int spi_hid_ll_parse(struct hid_device *hid)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	int ret;

	mutex_lock(&shid->ctrl_lock);
	ret = spi_hid_descriptor_request(shid,
			shid->dev.desc.report_descriptor_register);
	if (ret) {
		dev_err(&shid->spi->dev, "Expected report descriptor not received!\n");
	} else {
		ret = hid_parse_report(hid, shid->response.data,
				min(shid->response.len, shid->dev.desc.report_descriptor_length));
		if (ret)
			dev_err(&shid->spi->dev, "parsing report descriptor failed: %d\n", ret);
	}
	mutex_unlock(&shid->ctrl_lock);

	return ret;
}

/*
 * Send get/set_report request on the ctrl channel
 *
 * This function may not wait for rpm transitions as it may deadlock if
 * rpm_suspend is trying to remove the hid_device concurrently
 */
static int spi_hid_ll_raw_request(struct hid_device *hid, unsigned char reportnum,
			       __u8 *buf, size_t len, unsigned char rtype,
			       int reqtype)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	int ret = pm_runtime_get(&shid->spi->dev);
	if (ret <= 0) {
		// We've queued a wakeup but it's not active yet, the put will result
		// in a 200ms timer before suspending again. We ask userspace to try again
		// and hope that they hit that 200ms window.
		pm_runtime_put(&shid->spi->dev);
		return -EAGAIN;
	}
	mutex_lock(&shid->ctrl_lock);
	if (!shid->hid) {
		mutex_unlock(&shid->ctrl_lock);
		pm_runtime_put(&shid->spi->dev);
		dev_err(&shid->spi->dev, "%s called in unready state\n", __func__);
		return -ENODEV;
	}
	switch (reqtype) {
	case HID_REQ_SET_REPORT:
		if (buf[0] != reportnum) {
			dev_err(&shid->spi->dev, "%s report id missmatch\n", __func__);
			ret = -EINVAL;
		} else {
			ret = spi_hid_set_request(shid, &buf[1], len-1, reportnum);
		}
		break;
	case HID_REQ_GET_REPORT:
		ret = spi_hid_get_request(shid, reportnum);
		if (ret) break;
		memcpy(buf, shid->response.data, min(len, (size_t)shid->response.len));
		break;
	default:
		dev_err(&shid->spi->dev, "%s invalid request type\n", __func__);
		ret = -EIO;
	}
	mutex_unlock(&shid->ctrl_lock);
	pm_runtime_mark_last_busy(&shid->spi->dev);
	pm_runtime_put(&shid->spi->dev);
	return ret;
}

/*
 * This function may not wait for rpm transitions as it may deadlock if
 * rpm_suspend is trying to remove the hid_device concurrently
 */
static int spi_hid_ll_output_report(struct hid_device *hid,
		__u8 *buf, size_t len)
{
	int ret;
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	struct spi_hid_output_report report = {
		.content_type = SPI_HID_CONTENT_TYPE_OUTPUT_REPORT,
		.content_length = len-1,
		.content_id = buf[0],
		.content = &buf[1],
	};
	ret = pm_runtime_get(&shid->spi->dev);
	if (ret <= 0) {
		// We've queued a wakeup but it's not active yet, the put will result
		// in a 200ms timer before suspending again. We ask userspace to try again
		// and hope that they hit that 200ms window.
		pm_runtime_put(&shid->spi->dev);
		return -EAGAIN;
	}

	mutex_lock(&shid->ctrl_lock);
	if (shid->hid) {
		ret = spi_hid_dev_output_report(&shid->dev,
				shid->dev.desc.output_register, &report);
		pm_runtime_mark_last_busy(&shid->spi->dev);
	} else {
		dev_err(&shid->spi->dev, "%s called in unready state\n", __func__);
		ret = -ENODEV;
	}
	mutex_unlock(&shid->ctrl_lock);
	pm_runtime_put(&shid->spi->dev);
	if (ret > 0) return -ret;
	if (ret < 0) return ret;
	return len;
}

struct hid_ll_driver spi_hid_ll_driver = {
	.start = spi_hid_ll_start,
	.stop = spi_hid_ll_stop,
	.open = spi_hid_ll_open,
	.close = spi_hid_ll_close,
	.power = spi_hid_ll_power,
	.parse = spi_hid_ll_parse,
	.output_report = spi_hid_ll_output_report,
	.raw_request = spi_hid_ll_raw_request,
};

static struct hid_device *spi_hid_disconnect_hid(struct spi_hid *shid) {
	struct hid_device *hid = shid->hid;
	shid->hid = NULL;
	return hid;
}

static void spi_hid_stop_hid(struct spi_hid *shid)
{
	struct hid_device *hid;
	mutex_lock(&shid->ctrl_lock);
	mutex_lock(&shid->intr_lock);
	hid = spi_hid_disconnect_hid(shid);
	mutex_unlock(&shid->intr_lock);
	mutex_unlock(&shid->ctrl_lock);
	if (hid) hid_destroy_device(hid);
}

static void spi_hid_stop_dev(struct spi_hid *shid)
{
	spi_hid_async_response(shid, -ENODEV, NULL, 0);
	spi_hid_dev_stop(&shid->dev);
}

static void spi_hid_dev_error_work(struct work_struct *work)
{
	struct spi_hid *shid = container_of(work, struct spi_hid, dev_error_work);
	dev_err(&shid->spi->dev, "Device error occured, resetting\n");
	spi_hid_stop_hid(shid);
	spi_hid_stop_dev(shid);
	if (shid->attempts++ < SPI_HID_MAX_RESET_ATTEMPTS) {
		spi_hid_power_reset(&shid->pwr);
		spi_hid_power_restart(&shid->pwr);
		spi_hid_dev_start(&shid->dev);
	} else {
		dev_err(&shid->spi->dev,
				"More than %d device error reset attempts, aborting.\n",
				SPI_HID_MAX_RESET_ATTEMPTS);
		spi_hid_power_down(&shid->pwr);
	}
}

// Only purpose of reset callback is to ensure all usage of report buffers is finished
static void spi_hid_dev_reset_work(struct work_struct *work)
{
	struct spi_hid *shid = container_of(work, struct spi_hid, dev_reset_work);
	struct hid_device *hid;
	dev_err(&shid->spi->dev, "Device reset received, restarting\n");
	mutex_lock(&shid->ctrl_lock);
	mutex_lock(&shid->intr_lock);
	hid = spi_hid_disconnect_hid(shid);
	if (hid) pm_runtime_get(&shid->spi->dev);
	spi_hid_dev_restart(&shid->dev);
	mutex_unlock(&shid->intr_lock);
	mutex_unlock(&shid->ctrl_lock);
	if (hid) hid_destroy_device(hid);
}

static void spi_hid_dev_ready_work(struct work_struct *work)
{
	struct spi_hid *shid = container_of(work, struct spi_hid, dev_ready_work);
	struct hid_device *hid = hid_allocate_device();
	int ret;

	shid->attempts = 0;

	if (!hid || IS_ERR(hid)) {
		dev_err(&shid->spi->dev,
				"Failed to allocate hid device: %d\n", PTR_ERR(hid));
		return;
	}
	dev_dbg(&shid->spi->dev, "Received device descriptor\n");

	hid->driver_data = shid->spi;
	hid->ll_driver = &spi_hid_ll_driver;
	hid->dev.parent = &shid->spi->dev;
	hid->bus = BUS_SPI;
	hid->version = shid->dev.desc.hid_version;
	hid->vendor = shid->dev.desc.vendor_id;
	hid->product = shid->dev.desc.product_id;

	snprintf(hid->name, sizeof(hid->name), "spi %04hX:%04hX",
			hid->vendor, hid->product);
	strlcpy(hid->phys, dev_name(&shid->spi->dev), sizeof(hid->phys));

	mutex_lock(&shid->ctrl_lock);
	mutex_lock(&shid->intr_lock);
	shid->hid = hid;
	mutex_unlock(&shid->intr_lock);
	mutex_unlock(&shid->ctrl_lock);
	ret = hid_add_device(hid);
	if (ret) {
		dev_err(&shid->spi->dev, "Failed to add hid device: %d\n", ret);
		spi_hid_stop_hid(shid);
	}
	pm_runtime_put(&shid->spi->dev);
}

static void spi_hid_input_report_work(struct work_struct *work)
{
	struct spi_hid *shid = container_of(work, struct spi_hid, input_report_work);
	struct spi_hid_input_report report;
	int discarded;

	// intr_lock might be held by thread stopping _dev, if so,
	// discard input and release hi-prio work thread instead of blocking
	if (mutex_trylock(&shid->intr_lock)) {
		int cnt = 0;
		while (spi_hid_dev_get_input_report(&shid->dev, &report) == 0) {
			cnt++;
			if (shid->hid)
				hid_input_report(shid->hid, HID_INPUT_REPORT,
						report.content - 1, report.content_length + 1, 1);
		}
		discarded = spi_hid_dev_get_discarded(&shid->dev);
		if (discarded > 0)
			dev_warn(&shid->spi->dev, "%d input reports discarded, %d cnt\n", discarded, cnt);

		//UNCOMMENT for debug
		//dev_warn(&shid->spi->dev, "%d cnt %d dis\n", cnt, discarded);
		mutex_unlock(&shid->intr_lock);
	}

	pm_runtime_mark_last_busy(&shid->spi->dev);
}

static void spi_hid_response_work(struct work_struct *work)
{
	struct spi_hid *shid = container_of(work, struct spi_hid, response_work);
	struct spi_hid_input_report report;
	int res;

	pm_runtime_get(&shid->spi->dev);

	dev_err(&shid->spi->dev, "%s\n", __func__);

	res = spi_hid_dev_get_response(&shid->dev, &report);
	spi_hid_async_response(shid, res, report.content, report.content_length);

	pm_runtime_mark_last_busy(&shid->spi->dev);
	pm_runtime_put(&shid->spi->dev);
}

static int spi_hid_of_probe(struct spi_hid *shid)
{
	struct device *dev = &shid->spi->dev;
	u32 val;
	int ret;

	ret = of_property_read_u32(dev->of_node, "hid-descr-addr", &val);
	if (ret) {
		dev_err(&shid->spi->dev,
				"HID descriptor register address not provided\n");
		return -ENODEV;
	}
	dev_dbg(&shid->spi->dev, "hid-descr-addr: %d\n", val);
	shid->device_descriptor_register = val;

	ret = of_property_read_u32(dev->of_node, "sleep-timeout-ms", &val);
	if (ret) {
		dev_err(&shid->spi->dev,
				"sleep timeout value not provided\n");
		val = 0;
	} else {
		dev_dbg(&shid->spi->dev, "sleep-timeout-ms: %d\n", val);
	}
	shid->sleep_timeout_ms = val;

	return 0;
}

static const struct of_device_id spi_hid_of_match[] = {
	{ .compatible = "hid-over-spi" },
	{},
};
MODULE_DEVICE_TABLE(of, spi_hid_of_match);

static int spi_hid_probe(struct spi_device *spi)
{
	int ret;
	struct spi_hid *shid;

	dev_dbg(&spi->dev, "HID probe called for spi%d.%d\n",
			spi->master->bus_num, spi->chip_select);

	if (!spi->irq) {
		dev_err(&spi->dev,
			"HID over spi has not been provided an Int IRQ\n");
		return -EINVAL;
	}

	if (spi->irq < 0) {
		if (spi->irq != -EPROBE_DEFER)
			dev_err(&spi->dev,
				"HID over spi doesn't have a valid IRQ\n");
		return spi->irq;
	}

	shid = kzalloc(sizeof(struct spi_hid), GFP_KERNEL);
	if (!shid) {
		dev_err(&spi->dev, "Could not alloc spi-hid instance, out of memory\n");
		return -ENOMEM;
	}

	shid->spi = spi;
	spi_set_drvdata(spi, shid);

	ret = spi_hid_of_probe(shid);
	if (ret)
		goto err;

	mutex_init(&shid->ctrl_lock);
	mutex_init(&shid->intr_lock);

	init_waitqueue_head(&shid->response.wait);

	INIT_WORK(&shid->dev_error_work, spi_hid_dev_error_work);
	INIT_WORK(&shid->dev_reset_work, spi_hid_dev_reset_work);
	INIT_WORK(&shid->dev_ready_work, spi_hid_dev_ready_work);
	INIT_WORK(&shid->input_report_work, spi_hid_input_report_work);
	INIT_WORK(&shid->response_work, spi_hid_response_work);

	ret = spi_hid_power_init(&shid->pwr, &spi->dev);
	if (ret < 0)
		goto err;

	shid->dev.event_callback_context = shid;
	shid->dev.event_callback = spi_hid_callback_dev_event;

	spi_hid_dev_init(&shid->dev, shid->spi, shid->device_descriptor_register);

	pm_runtime_set_suspended(&shid->spi->dev);
	pm_runtime_use_autosuspend(&shid->spi->dev);
	pm_runtime_set_autosuspend_delay(&shid->spi->dev, shid->sleep_timeout_ms);
	pm_suspend_ignore_children(&shid->spi->dev, true);
	device_init_wakeup(&shid->spi->dev, true);
	dev_pm_set_wake_irq(&shid->spi->dev, shid->spi->irq);
	pm_runtime_enable(&shid->spi->dev);
	pm_runtime_forbid(&shid->spi->dev);
	device_enable_async_suspend(&shid->spi->dev);
	return 0;

err:
	return ret;
}

static int spi_hid_remove(struct spi_device *spi)
{
	struct spi_hid *shid = spi_get_drvdata(spi);

	spi_hid_stop_hid(shid);
	pm_runtime_force_suspend(&shid->spi->dev);
	pm_runtime_allow(&shid->spi->dev);
	dev_pm_clear_wake_irq(&shid->spi->dev);
	pm_suspend_ignore_children(&shid->spi->dev, false);
	pm_runtime_put_noidle(&shid->spi->dev);
	spi_hid_dev_destroy(&shid->dev);
	kfree(shid);
	return 0;
}

static int spi_hid_suspend(struct device *dev)
{
	return pm_runtime_force_suspend(dev);
}

static int spi_hid_resume(struct device *dev)
{
	return pm_runtime_force_resume(dev);
}

static int spi_hid_runtime_suspend(struct device *dev)
{
	struct spi_device *spi = to_spi_device(dev);
	struct spi_hid *shid = spi_get_drvdata(spi);
	mutex_lock(&shid->ctrl_lock);
	if (shid->hid && pm_runtime_active(&shid->hid->dev)) {
		dev_err(&shid->spi->dev, "%s ->d2\n", __func__);
		spi_hid_power_mode(shid, SPI_HID_POWER_MODE_SLEEP);
		spi_hid_dev_asleep(&shid->dev);
		mutex_unlock(&shid->ctrl_lock);
	} else if (shid->hid && device_may_wakeup(&shid->spi->dev)) {
		dev_err(&shid->spi->dev, "%s ->d3*\n", __func__);
		spi_hid_power_mode(shid, SPI_HID_POWER_MODE_WAKING_SLEEP);
		spi_hid_dev_asleep(&shid->dev);
		mutex_unlock(&shid->ctrl_lock);
	} else {
		dev_err(&shid->spi->dev, "%s ->d3\n", __func__);
		set_bit(SPI_HID_DEV_IN_D3, &shid->dev.flags);
		mutex_unlock(&shid->ctrl_lock);
		spi_hid_stop_hid(shid);
		spi_hid_stop_dev(shid);
		spi_hid_power_down(&shid->pwr);
	}

	return 0;
}

static int spi_hid_runtime_resume(struct device *dev)
{
	struct spi_device *spi = to_spi_device(dev);
	struct spi_hid *shid = spi_get_drvdata(spi);
	dev_err(&shid->spi->dev, "%s ->d0\n", __func__);
	clear_bit(SPI_HID_DEV_IN_D3, &shid->dev.flags);
	mutex_lock(&shid->ctrl_lock);
	if (shid->hid) {
		spi_hid_dev_awake(&shid->dev);
		spi_hid_power_mode(shid, SPI_HID_POWER_MODE_ACTIVE);
		if (spi_hid_dev_clear_wakeup(&shid->dev)) {
			pm_relax(&shid->spi->dev);
			pm_runtime_mark_last_busy(&shid->spi->dev);
			pm_runtime_put(&shid->spi->dev);
		}
		mutex_unlock(&shid->ctrl_lock);
	} else {
		mutex_unlock(&shid->ctrl_lock);
		dev_err(&shid->spi->dev, "%s power up\n", __func__);
		pm_runtime_get(&shid->spi->dev); // Hold rpm resumed until _hid is up.
		spi_hid_power_up(&shid->pwr);
		spi_hid_dev_start(&shid->dev);
	}
	return 0;
}

static int spi_hid_runtime_idle(struct device *dev)
{
	struct spi_device *spi = to_spi_device(dev);
	struct spi_hid *shid = spi_get_drvdata(spi);
	mutex_lock(&shid->ctrl_lock);
	if (!shid->hid) {
		mutex_unlock(&shid->ctrl_lock);
		return 0;
	} else if (pm_runtime_active(&shid->hid->dev)) {
		mutex_unlock(&shid->ctrl_lock);
		pm_runtime_autosuspend(&shid->spi->dev);
		return 1;
	} else {
		mutex_unlock(&shid->ctrl_lock);
		pm_schedule_suspend(&shid->spi->dev, 200);
		return 1;
	}
}

static const struct dev_pm_ops spi_hid_pm = {
	SET_SYSTEM_SLEEP_PM_OPS(spi_hid_suspend, spi_hid_resume)
	SET_RUNTIME_PM_OPS(
		spi_hid_runtime_suspend,
		spi_hid_runtime_resume,
		spi_hid_runtime_idle
	)
};

static const struct spi_device_id spi_hid_id_table[] = {
	{ "hid", 0 },
	{ "hid-over-spi", 0 },
	{ },
};
MODULE_DEVICE_TABLE(spi, spi_hid_id_table);

static struct spi_driver spi_hid_driver = {
	.driver = {
		.name	= "spi_hid",
		.pm	= &spi_hid_pm,
		.owner	= THIS_MODULE,
		.of_match_table = of_match_ptr(spi_hid_of_match),
	},
	.probe		= spi_hid_probe,
	.remove		= spi_hid_remove,
	.id_table	= spi_hid_id_table,
};

module_spi_driver(spi_hid_driver);

MODULE_DESCRIPTION("HID over SPI transport driver");
MODULE_LICENSE("GPL");
