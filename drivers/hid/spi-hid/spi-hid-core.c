// SPDX-License-Identifier: GPL-2.0
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
#include <linux/pinctrl/consumer.h>
#include <linux/regulator/consumer.h>
#include <linux/workqueue.h>
#include <linux/dma-mapping.h>
#include <linux/crc32.h>

#include "spi-hid-core.h"
#include "spi-hid_trace.h"
#include "../hid-ids.h"

#define SPI_HID_MAX_RESET_ATTEMPTS 3

static struct hid_ll_driver spi_hid_ll_driver;

static void spi_hid_parse_dev_desc(struct spi_hid_device_desc_raw *raw,
		struct spi_hid_device_descriptor *desc)
{
	desc->hid_version = le16_to_cpu(raw->bcdVersion);
	desc->report_descriptor_length = le16_to_cpu(raw->wReportDescLength);
	desc->report_descriptor_register =
		le16_to_cpu(raw->wReportDescRegister);
	desc->input_register = le16_to_cpu(raw->wInputRegister);
	desc->max_input_length = le16_to_cpu(raw->wMaxInputLength);
	desc->output_register = le16_to_cpu(raw->wOutputRegister);
	desc->max_output_length = le16_to_cpu(raw->wMaxOutputLength);
	desc->command_register = le16_to_cpu(raw->wCommandRegister);
	desc->vendor_id = le16_to_cpu(raw->wVendorID);
	desc->product_id = le16_to_cpu(raw->wProductID);
	desc->version_id = le16_to_cpu(raw->wVersionID);
	desc->device_power_support = 0;
	desc->power_response_delay = 0;
}

static void spi_hid_populate_input_header(__u8 *buf,
		struct spi_hid_input_header *header)
{
	header->version       = (buf[0] >> 0) & 0xf;
	header->report_type   = (buf[0] >> 4) & 0xf;
	header->fragment_id   = (buf[1] >> 0) & 0xf;
	header->report_length = ((((buf[1] >> 4) & 0xf) << 0) |
			(buf[2] << 4)) * 4;
	header->sync_const    = buf[3];
}

static void spi_hid_populate_input_body(__u8 *buf,
		struct spi_hid_input_body *body)
{
	body->content_length = (buf[0] | (buf[1] << 8)) -
		(sizeof(body->content_length) + sizeof(body->content_id));
	body->content_id = buf[2];
}

static void spi_hid_input_report_prepare(struct spi_hid_input_buf *buf,
		struct spi_hid_input_report *report)
{
	struct spi_hid_input_header header;
	struct spi_hid_input_body body;

	spi_hid_populate_input_header(buf->header, &header);
	spi_hid_populate_input_body(buf->body, &body);
	report->report_type = header.report_type;
	report->content_length = body.content_length;
	report->content_id = body.content_id;
	report->content = buf->content;
}

static void spi_hid_output_header(__u8 *buf,
		u16 output_register, u16 output_report_length)
{
	buf[0] = SPI_HID_OUTPUT_HEADER_OPCODE_WRITE;
	buf[1] = (output_register >> 16) & 0xff;
	buf[2] = (output_register >> 8) & 0xff;
	buf[3] = (output_register >> 0) & 0xff;
	buf[4] = (SPI_HID_OUTPUT_HEADER_VERSION << 0) |
			(((output_report_length >> 0) & 0xf) << 4);
	buf[5] = (output_report_length >> 4) & 0xff;
}

static void spi_hid_output_body(__u8 *buf,
		struct spi_hid_output_report *report)
{
	u16 content_length = report->content_length;

	buf[0] = report->content_type;
	buf[1] = (content_length >> 0) & 0xff;
	buf[2] = (content_length >> 8) & 0xff;
	buf[3] = report->content_id;
}

static void spi_hid_read_approval(u32 input_register, u8 *buf)
{
	buf[0] = SPI_HID_READ_APPROVAL_OPCODE_READ;
	buf[1] = (input_register >> 16) & 0xff;
	buf[2] = (input_register >> 8) & 0xff;
	buf[3] = (input_register >> 0) & 0xff;
	buf[4] = SPI_HID_READ_APPROVAL_CONSTANT;
}

static int spi_hid_input_async(struct spi_hid *shid, void *buf, u16 length,
		void (*complete)(void*))
{
	int ret;

	shid->input_transfer[0].tx_buf = shid->read_approval;
	shid->input_transfer[0].len = SPI_HID_READ_APPROVAL_LEN;

	shid->input_transfer[1].rx_buf = buf;
	shid->input_transfer[1].len = length;

	/*
	 * Optimization opportunity: we really do not need the input_register
	 * field in struct spi_hid; we can calculate the read_approval field
	 * with default input_register value during probe and then re-calculate
	 * from spi_hid_parse_dev_desc. And then we can get rid of the below
	 * spi_hid_read_approval call which is run twice per interrupt.
	 *
	 * Long term, for spec v1.0, we'll be using the input_register value
	 * from device tree, not from the device descriptor.
	 */
	spi_hid_read_approval(shid->desc.input_register,
			shid->read_approval);
	spi_message_init_with_transfers(&shid->input_message,
			shid->input_transfer, 2);

	shid->input_message.complete = complete;
	shid->input_message.context = shid;

	trace_spi_hid_input_async(shid,
			shid->input_transfer[0].tx_buf,
			shid->input_transfer[0].len,
			shid->input_transfer[1].rx_buf,
			shid->input_transfer[1].len, 0);

	ret = spi_async(shid->spi, &shid->input_message);
	if (ret) {
		shid->bus_error_count++;
		shid->bus_last_error = ret;
	}

	return ret;
}

static int spi_hid_output(struct spi_hid *shid, void *buf, u16 length)
{
	struct spi_transfer transfer;
	struct spi_message message;
	int ret;

	memset(&transfer, 0, sizeof(transfer));

	transfer.tx_buf = buf;
	transfer.len = length;

	spi_message_init_with_transfers(&message, &transfer, 1);

	/*
	 * REVISIT: Should output be asynchronous?
	 *
	 * According to Documentation/hid/hid-transport.rst, ->output_report()
	 * must be implemented as an asynchronous operation.
	 */
	trace_spi_hid_output_begin(shid, transfer.tx_buf,
			transfer.len, NULL, 0, 0);

	ret = spi_sync(shid->spi, &message);

	trace_spi_hid_output_end(shid, transfer.tx_buf,
			transfer.len, NULL, 0, ret);

	if (ret) {
		shid->bus_error_count++;
		shid->bus_last_error = ret;
	}

	return ret;
}

static const char *const spi_hid_power_mode_string(u8 power_state)
{
	switch (power_state) {
	case SPI_HID_POWER_MODE_ACTIVE:
		return "d0";
	case SPI_HID_POWER_MODE_SLEEP:
		return "d2";
	case SPI_HID_POWER_MODE_OFF:
		return "d3";
	case SPI_HID_POWER_MODE_WAKING_SLEEP:
		return "d3*";
	default:
		return "unknown";
	}
}

static int spi_hid_power_down(struct spi_hid *shid)
{
	struct device *dev = &shid->spi->dev;
	int ret;

	if (!shid->powered)
		return 0;

	pinctrl_select_state(shid->pinctrl, shid->pinctrl_sleep);

	ret = regulator_disable(shid->supply);
	if (ret) {
		dev_err(dev, "failed to disable regulator\n");
		return ret;
	}

	shid->powered = false;

	return 0;
}

static struct hid_device *spi_hid_disconnect_hid(struct spi_hid *shid)
{
	struct hid_device *hid = shid->hid;

	shid->hid = NULL;

	return hid;
}

static void spi_hid_stop_hid(struct spi_hid *shid)
{
	struct hid_device *hid;

	hid = spi_hid_disconnect_hid(shid);
	if (hid) {
		cancel_work_sync(&shid->create_device_work);
		cancel_work_sync(&shid->refresh_device_work);
		hid_destroy_device(hid);
	}
}

static int spi_hid_error_handler(struct spi_hid *shid)
{
	struct device *dev = &shid->spi->dev;
	int ret;

	if (shid->power_state == SPI_HID_POWER_MODE_OFF)
		return 0;

	dev_err(dev, "Error Handler\n");

	if (shid->attempts++ >= SPI_HID_MAX_RESET_ATTEMPTS) {
		dev_err(dev, "unresponsive device, aborting.\n");
		spi_hid_stop_hid(shid);
		spi_hid_power_down(shid);

		return -ESHUTDOWN;
	}

	shid->ready = false;
	sysfs_notify(&dev->kobj, NULL, "ready");

	ret = pinctrl_select_state(shid->pinctrl, shid->pinctrl_reset);
	if (ret) {
		dev_err(dev, "Power Reset failed\n");
		return ret;
	}
	shid->power_state = SPI_HID_POWER_MODE_OFF;
	shid->input_stage = SPI_HID_INPUT_STAGE_IDLE;
	shid->input_transfer_pending = 0;
	cancel_work_sync(&shid->reset_work);

	/* Drive reset for at least 100 ms */
	msleep(100);

	shid->power_state = SPI_HID_POWER_MODE_ACTIVE;
	ret = pinctrl_select_state(shid->pinctrl, shid->pinctrl_active);
	if (ret) {
		dev_err(dev, "Power Restart failed\n");
		return ret;
	}

	return 0;
}

static void spi_hid_error_work(struct work_struct *work)
{
	struct spi_hid *shid = container_of(work, struct spi_hid, error_work);
	struct device *dev = &shid->spi->dev;
	int ret;

	ret = spi_hid_error_handler(shid);
	if (ret)
		dev_err(dev, "%s: error handler failed\n", __func__);
}

/**
 * Handle the reset response from the FW by sending a request for the device
 * descriptor.
 * @shid: a pointer to the driver context
 */
static void spi_hid_reset_work(struct work_struct *work)
{
	struct spi_hid *shid =
		container_of(work, struct spi_hid, reset_work);
	struct device *dev = &shid->spi->dev;
	struct spi_hid_output_buf *buf = &shid->output;
	int ret;

	trace_spi_hid_reset_work(shid);

	dev_dbg(dev, "Reset Handler\n");
	if (shid->ready) {
		dev_err(dev, "Spontaneous FW reset!");
		shid->ready = false;
		shid->dir_count++;
		sysfs_notify(&dev->kobj, NULL, "ready");
	}

	if (flush_work(&shid->create_device_work))
		dev_err(dev, "Reset handler waited for create_device_work");

	if (shid->power_state == SPI_HID_POWER_MODE_OFF) {
		return;
	}

	if (flush_work(&shid->refresh_device_work))
		dev_err(dev, "Reset handler waited for refresh_device_work");

	memset(&buf->body, 0x00, SPI_HID_OUTPUT_BODY_LEN);
	spi_hid_output_header(buf->header, shid->hid_desc_addr,
			round_up(sizeof(buf->body), 4));
	ret =  spi_hid_output(shid, buf, SPI_HID_OUTPUT_HEADER_LEN +
			SPI_HID_OUTPUT_BODY_LEN);
	if (ret) {
		dev_err(dev, "failed to send device descriptor request\n");
		spi_hid_error_handler(shid);
		return;
	}
}

static int spi_hid_input_report_handler(struct spi_hid *shid,
		struct spi_hid_input_buf *buf)
{
	struct device *dev = &shid->spi->dev;
	struct spi_hid_input_report r;
	int ret;

	dev_dbg(dev, "Input Report Handler\n");

	trace_spi_hid_input_report_handler(shid);

	if (!shid->ready) {
		dev_err(dev, "discarding input report, not ready!\n");
		return 0;
	}

	if (shid->refresh_in_progress) {
		dev_err(dev, "discarding input report, refresh in progress!\n");
		return 0;
	}

	if (!shid->hid) {
		dev_err(dev, "discarding input report, no HID device!\n");
		return 0;
	}

	spi_hid_input_report_prepare(buf, &r);

	ret = hid_input_report(shid->hid, HID_INPUT_REPORT,
			r.content - 1,
			r.content_length + 1, 1);

	if (ret == -ENODEV || ret == -EBUSY) {
		dev_err(dev, "ignoring report --> %d\n", ret);
		return 0;
	}

	return ret;
}

static int spi_hid_response_handler(struct spi_hid *shid,
		struct spi_hid_input_buf *buf)
{
	trace_spi_hid_response_handler(shid);
	dev_dbg(&shid->spi->dev, "Response Handler\n");

	/* completion_done returns 0 if there are waiters, otherwise 1 */
	if (completion_done(&shid->output_done))
		dev_err(&shid->spi->dev, "Unexpected response report\n");
	else
		complete(&shid->output_done);

	return 0;
}

static int spi_hid_send_output_report(struct spi_hid *shid, u32 output_register,
		struct spi_hid_output_report *report)
{
	struct spi_hid_output_buf *buf = &shid->output;
	struct device *dev = &shid->spi->dev;

	u16 padded_length;
	u16 body_length;
	u8 padding;
	u16 max_length;

	int ret;

	body_length = sizeof(buf->body) + report->content_length;
	padded_length = round_up(body_length, 4);
	padding = padded_length - body_length;
	max_length = round_up(shid->desc.max_output_length + 3
						+ sizeof(buf->body), 4);

	if (padded_length > max_length) {
		dev_err(dev, "Output report too big\n");
		ret = -E2BIG;
		goto out;
	}

	spi_hid_output_header(buf->header, output_register, padded_length);
	spi_hid_output_body(buf->body, report);

	if (report->content_length - 3)
		memcpy(&buf->content, report->content, report->content_length);

	memset(&buf->content[report->content_length], 0, padding);

	ret = spi_hid_output(shid, buf, sizeof(buf->header) +
			padded_length);
	if (ret) {
		dev_err(dev, "failed output transfer\n");
		goto out;
	}

	return 0;

out:
	return ret;
}

/*
* This function shouldn't be called from the interrupt thread context since it
* waits for completion that gets completed in one of the future runs of the
* interrupt thread.
*/
static int spi_hid_sync_request(struct spi_hid *shid, u16 output_register,
		struct spi_hid_output_report *report)
{
	struct device *dev = &shid->spi->dev;
	int ret = 0;


	ret = spi_hid_send_output_report(shid, output_register,
			report);
	if (ret) {
		dev_err(dev, "failed to transfer output report\n");
		return ret;
	}

	mutex_unlock(&shid->lock);
	ret = wait_for_completion_interruptible_timeout(&shid->output_done,
			msecs_to_jiffies(1000));
	mutex_lock(&shid->lock);
	if (ret == 0) {
		dev_err(dev, "response timed out\n");
		spi_hid_error_handler(shid);
		return -ETIMEDOUT;
	}

	return 0;
}

/*
* This function returns the length of the report descriptor, or a negative
* error code if something went wrong.
*/
static int spi_hid_report_descriptor_request(struct spi_hid *shid)
{
	int ret;
	struct device *dev = &shid->spi->dev;
	struct spi_hid_output_report report = {
		.content_type = SPI_HID_CONTENT_TYPE_COMMAND,
		.content_length = 3,
		.content_id = 0,
		.content = NULL,
	};


	ret =  spi_hid_sync_request(shid,
			shid->desc.report_descriptor_register, &report);
	if (ret) {
		dev_err(dev, "Expected report descriptor not received!\n");
		goto out;
	}

	ret = (shid->response.body[0] | (shid->response.body[1] << 8)) - 3;
	if (ret != shid->desc.report_descriptor_length) {
		dev_err(dev, "Received report descriptor length doesn't match device descriptor field, using min of the two\n");
		ret = min_t(unsigned int, ret,
			shid->desc.report_descriptor_length);
	}
out:
	return ret;
}

static int spi_hid_process_input_report(struct spi_hid *shid,
		struct spi_hid_input_buf *buf)
{
	struct spi_hid_input_header header;
	struct spi_hid_input_body body;
	struct device *dev = &shid->spi->dev;
	struct spi_hid_device_desc_raw *raw;
	int ret;

	trace_spi_hid_process_input_report(shid);

	spi_hid_populate_input_header(buf->header, &header);
	spi_hid_populate_input_body(buf->body, &body);

	if (body.content_length > header.report_length) {
		dev_err(dev, "Bad body length %d > %d\n", body.content_length,
							header.report_length);
		return -EINVAL;
	}

	if (body.content_id == SPI_HID_HEARTBEAT_REPORT_ID) {
		dev_warn(dev, "Heartbeat ID 0x%x from device %u\n",
			buf->content[1], buf->content[0]);
	}

	switch (header.report_type) {
	case SPI_HID_REPORT_TYPE_DATA:
		ret = spi_hid_input_report_handler(shid, buf);
		break;
	case SPI_HID_REPORT_TYPE_RESET_RESP:
		schedule_work(&shid->reset_work);
		ret = 0;
		break;
	case SPI_HID_REPORT_TYPE_DEVICE_DESC:
		dev_dbg(dev, "Received device descriptor\n");
		/* Reset attempts at every device descriptor fetch */
		shid->attempts = 0;
		raw = (struct spi_hid_device_desc_raw *) buf->content;
		spi_hid_parse_dev_desc(raw, &shid->desc);
		if (!shid->hid) {
			schedule_work(&shid->create_device_work);
		} else {
			schedule_work(&shid->refresh_device_work);
		}
		ret = 0;
		break;
	case SPI_HID_REPORT_TYPE_COMMAND_RESP:
	case SPI_HID_REPORT_TYPE_GET_FEATURE_RESP:
		if (!shid->ready) {
			dev_err(dev,
				"Unexpected response report type while not ready: 0x%x\n",
				header.report_type);
			ret = -EINVAL;
			break;
		}
		/* fall through */
	case SPI_HID_REPORT_TYPE_REPORT_DESC:
		ret = spi_hid_response_handler(shid, buf);
		break;
	default:
		dev_err(dev, "Unknown input report: 0x%x\n", header.report_type);
		ret = -EINVAL;
		break;
	}


	return ret;
}

static int spi_hid_bus_validate_header(struct spi_hid *shid, struct spi_hid_input_header *header)
{
	struct device *dev = &shid->spi->dev;

	if (header->sync_const != SPI_HID_INPUT_HEADER_SYNC_BYTE) {
		dev_err(dev, "Invalid input report sync constant (0x%x)\n",
				header->sync_const);
		return -EINVAL;
	}

	if (header->version != SPI_HID_INPUT_HEADER_VERSION) {
		dev_err(dev, "Unknown input report version (v 0x%x)\n",
				header->version);
		return -EINVAL;
	}

	if (shid->desc.max_input_length != 0 && header->report_length > shid->desc.max_input_length) {
		dev_err(dev, "Report body of size %u larger than max expected of %u\n",
				header->report_length, shid->desc.max_input_length);
		return -EMSGSIZE;
	}

	return 0;
}

static int spi_hid_create_device(struct spi_hid *shid)
{
	struct hid_device *hid;
	struct device *dev = &shid->spi->dev;
	int ret;

	hid = hid_allocate_device();

	if (IS_ERR(hid)) {
		dev_err(dev, "Failed to allocate hid device: %ld\n",
				PTR_ERR(hid));
		ret = PTR_ERR(hid);
		return ret;
	}

	hid->driver_data = shid->spi;
	hid->ll_driver = &spi_hid_ll_driver;
	hid->dev.parent = &shid->spi->dev;
	hid->bus = BUS_SPI;
	hid->version = shid->desc.hid_version;
	hid->vendor = shid->desc.vendor_id;
	hid->product = shid->desc.product_id;

	snprintf(hid->name, sizeof(hid->name), "spi %04hX:%04hX",
			hid->vendor, hid->product);
	strscpy(hid->phys, dev_name(&shid->spi->dev), sizeof(hid->phys));

	shid->hid = hid;

	ret = hid_add_device(hid);
	if (ret) {
		dev_err(dev, "Failed to add hid device: %d\n", ret);
		/*
		* We likely got here because report descriptor request timed
		* out. Let's disconnect and destroy the hid_device structure.
		*/
		hid = spi_hid_disconnect_hid(shid);
		if (hid)
			hid_destroy_device(hid);
		return ret;
	}

	return 0;
}

static void spi_hid_create_device_work(struct work_struct *work)
{
	struct spi_hid *shid =
		container_of(work, struct spi_hid, create_device_work);
	struct device *dev = &shid->spi->dev;
	u8 prev_state = shid->power_state;
	int ret;

	trace_spi_hid_create_device_work(shid);
	dev_dbg(dev, "Create device work\n");

	if (shid->desc.hid_version != SPI_HID_SUPPORTED_VERSION) {
		dev_err(dev, "Unsupported device descriptor version %4x\n",
			shid->desc.hid_version);
		ret = spi_hid_error_handler(shid);
		if (ret)
			dev_err(dev, "%s: error handler failed\n", __func__);
		return;
	}

	ret = spi_hid_create_device(shid);
	if (ret) {
		dev_err(dev, "Failed to create hid device\n");
		return;
	}

	shid->attempts = 0;
	if (shid->irq_enabled) {
		disable_irq(shid->spi->irq);
		shid->irq_enabled = false;
	} else {
		dev_err(dev, "%s called with interrupt already disabled\n",
								__func__);
		shid->logic_error_count++;
		shid->logic_last_error = -ENOEXEC;
	}
	ret = spi_hid_power_down(shid);
	if (ret) {
		dev_err(dev, "%s: could not power down\n", __func__);
		return;
	}

	shid->power_state = SPI_HID_POWER_MODE_OFF;
	dev_err(dev, "%s: %s -> %s\n", __func__,
			spi_hid_power_mode_string(prev_state),
			spi_hid_power_mode_string(shid->power_state));
}

static void spi_hid_refresh_device_work(struct work_struct *work)
{
	struct spi_hid *shid =
		container_of(work, struct spi_hid, refresh_device_work);
	struct device *dev = &shid->spi->dev;
	struct hid_device *hid;
	int ret;
	u32 new_crc32;

	trace_spi_hid_refresh_device_work(shid);
	dev_dbg(dev, "Refresh device work\n");

	if (shid->desc.hid_version != SPI_HID_SUPPORTED_VERSION) {
		dev_err(dev, "Unsupported device descriptor version %4x\n",
			shid->desc.hid_version);
		ret = spi_hid_error_handler(shid);
		if (ret)
			dev_err(dev, "%s: error handler failed\n", __func__);
		return;
	}

	mutex_lock(&shid->lock);
	ret = spi_hid_report_descriptor_request(shid);
	mutex_unlock(&shid->lock);
	if (ret < 0) {
		dev_err(dev, "Refresh: failed report descriptor request, error %d", ret);
		return;
	}

	new_crc32 = crc32_le(0, (unsigned char const *) shid->response.content, (size_t)ret);
	if (new_crc32 == shid->report_descriptor_crc32)
	{
		dev_dbg(dev, "Refresh device work - returning\n");
		shid->ready = true;
		sysfs_notify(&dev->kobj, NULL, "ready");
		return;
	}

	dev_err(dev, "Re-creating the HID device\n");

	shid->report_descriptor_crc32 = new_crc32;
	shid->refresh_in_progress = true;

	hid = spi_hid_disconnect_hid(shid);
	if (hid) {
		hid_destroy_device(hid);
	}

	ret = spi_hid_create_device(shid);
	if (ret)
		dev_err(dev, "Failed to create hid device\n");

	shid->refresh_in_progress = false;
	shid->ready = true;
	sysfs_notify(&dev->kobj, NULL, "ready");
}

static void spi_hid_input_header_complete(void *_shid);

static void spi_hid_input_body_complete(void *_shid)
{
	struct spi_hid *shid = _shid;
	struct device *dev = &shid->spi->dev;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&shid->input_lock, flags);
	if (!shid->powered)
		goto out;

	trace_spi_hid_input_body_complete(shid,
			shid->input_transfer[0].tx_buf,
			shid->input_transfer[0].len,
			shid->input_transfer[1].rx_buf,
			shid->input_transfer[1].len,
			shid->input_message.status);

	shid->input_stage = SPI_HID_INPUT_STAGE_IDLE;

	if (shid->input_message.status < 0) {
		dev_warn(dev, "error reading body, resetting %d\n",
				shid->input_message.status);
		shid->bus_error_count++;
		shid->bus_last_error = shid->input_message.status;
		schedule_work(&shid->error_work);
		goto out;
	}

	if (shid->power_state == SPI_HID_POWER_MODE_OFF) {
		dev_warn(dev, "input body complete called while device is "
				"off\n");
		goto out;
	}

	ret = spi_hid_process_input_report(shid, &shid->input);
	if (ret) {
		dev_err(dev, "failed input callback: %d\n", ret);
		schedule_work(&shid->error_work);
		goto out;
	}

	if (--shid->input_transfer_pending) {
		struct spi_hid_input_buf *buf = &shid->input;

		ret = spi_hid_input_async(shid, buf->header,
				sizeof(buf->header),
				spi_hid_input_header_complete);
		if (ret)
			dev_err(dev, "failed to start header --> %d\n", ret);
	}

out:
	spin_unlock_irqrestore(&shid->input_lock, flags);
}

static void spi_hid_input_header_complete(void *_shid)
{
	struct spi_hid *shid = _shid;
	struct device *dev = &shid->spi->dev;
	struct spi_hid_input_header header;
	struct spi_hid_input_buf *buf;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&shid->input_lock, flags);
	if (!shid->powered)
		goto out;

	trace_spi_hid_input_header_complete(shid,
			shid->input_transfer[0].tx_buf,
			shid->input_transfer[0].len,
			shid->input_transfer[1].rx_buf,
			shid->input_transfer[1].len,
			shid->input_message.status);

	if (shid->input_message.status < 0) {
		dev_warn(dev, "error reading header, resetting %d\n",
				shid->input_message.status);
		shid->bus_error_count++;
		shid->bus_last_error = shid->input_message.status;
		schedule_work(&shid->error_work);
		goto out;
	}

	if (shid->power_state == SPI_HID_POWER_MODE_OFF) {
		dev_warn(dev, "input header complete called while device is "
				"off\n");
		goto out;
	}

	spi_hid_populate_input_header(shid->input.header, &header);

	ret = spi_hid_bus_validate_header(shid, &header);
	if (ret) {
		dev_err(dev, "failed to validate header: %d\n", ret);
		print_hex_dump(KERN_ERR, "spi_hid: header buffer: ",
						DUMP_PREFIX_NONE, 16, 1,
						shid->input.header,
						sizeof(shid->input.header),
						false);
		shid->bus_error_count++;
		shid->bus_last_error = ret;
		goto out;
	}

	buf = &shid->input;
	if (header.report_type == SPI_HID_REPORT_TYPE_COMMAND_RESP ||
		header.report_type == SPI_HID_REPORT_TYPE_GET_FEATURE_RESP ||
		header.report_type == SPI_HID_REPORT_TYPE_REPORT_DESC) {
			buf = &shid->response;
			memcpy(shid->response.header, shid->input.header,
					sizeof(shid->input.header));
	}

	shid->input_stage = SPI_HID_INPUT_STAGE_BODY;

	ret = spi_hid_input_async(shid, buf->body, header.report_length,
			spi_hid_input_body_complete);
	if (ret)
		dev_err(dev, "failed body async transfer: %d\n", ret);

out:
	if (ret)
		shid->input_transfer_pending = 0;

	spin_unlock_irqrestore(&shid->input_lock, flags);
}

static int spi_hid_bus_input_report(struct spi_hid *shid)
{
	struct device *dev = &shid->spi->dev;
	int ret;

	trace_spi_hid_bus_input_report(shid);
	if (shid->input_transfer_pending++)
		return 0;

	ret = spi_hid_input_async(shid, shid->input.header,
			sizeof(shid->input.header),
			spi_hid_input_header_complete);
	if (ret) {
		dev_err(dev, "Failed to receive header: %d\n", ret);
		return ret;
	}

	return 0;
}

static int spi_hid_assert_reset(struct spi_hid *shid)
{
	int ret;

	ret = pinctrl_select_state(shid->pinctrl, shid->pinctrl_reset);
	if (ret)
		return ret;

	/* Let VREG_TS_5V0 stabilize */
	usleep_range(10000, 11000);

	return 0;
}

static int spi_hid_deassert_reset(struct spi_hid *shid)
{
	int ret;

	ret = pinctrl_select_state(shid->pinctrl, shid->pinctrl_active);
	if (ret)
		return ret;

	/* Let VREG_S10B_1P8V stabilize */
	usleep_range(5000, 6000);

	return 0;
}

static int spi_hid_power_up(struct spi_hid *shid)
{
	int ret;

	if (shid->powered)
		return 0;

	shid->input_transfer_pending = 0;
	shid->powered = true;

	ret = regulator_enable(shid->supply);
	if (ret) {
		shid->regulator_error_count++;
		shid->regulator_last_error = ret;
		goto err0;
	}

	/* Let VREG_S10B_1P8V stabilize */
	usleep_range(5000, 6000);

	return 0;

err0:
	shid->powered = false;

	return ret;
}

static int spi_hid_get_request(struct spi_hid *shid, u8 content_id)
{
	struct spi_hid_output_report report = {
		.content_type = SPI_HID_CONTENT_TYPE_GET_FEATURE,
		.content_length = 3,
		.content_id = content_id,
		.content = NULL,
	};


	return spi_hid_sync_request(shid, shid->desc.output_register,
			&report);
}

static int spi_hid_set_request(struct spi_hid *shid,
		u8 *arg_buf, u16 arg_len, u8 content_id)
{
	struct spi_hid_output_report report = {
		.content_type = SPI_HID_CONTENT_TYPE_SET_FEATURE,
		.content_length = arg_len + 3,
		.content_id = content_id,
		.content = arg_buf,
	};


	return spi_hid_send_output_report(shid,
			shid->desc.output_register, &report);
}

static irqreturn_t spi_hid_dev_irq(int irq, void *_shid)
{
	struct spi_hid *shid = _shid;
	struct device *dev = &shid->spi->dev;
	int ret = 0;

	spin_lock(&shid->input_lock);
	trace_spi_hid_dev_irq(shid, irq);

	ret = spi_hid_bus_input_report(shid);

	if (ret) {
		dev_err(dev, "Input transaction failed: %d\n", ret);
		schedule_work(&shid->error_work);
	}
	spin_unlock(&shid->input_lock);

	return IRQ_HANDLED;
}

/* hid_ll_driver interface functions */

static int spi_hid_ll_start(struct hid_device *hid)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);

	if (shid->desc.max_input_length < HID_MIN_BUFFER_SIZE) {
		dev_err(&shid->spi->dev, "HID_MIN_BUFFER_SIZE > max_input_length (%d)\n",
				shid->desc.max_input_length);
		return -EINVAL;
	}

	return 0;
}

static void spi_hid_ll_stop(struct hid_device *hid)
{
	hid->claimed = 0;
}

static int spi_hid_ll_open(struct hid_device *hid)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	u8 prev_state = shid->power_state;
	int ret;

	if (shid->refresh_in_progress || prev_state == SPI_HID_POWER_MODE_ACTIVE)
		return 0;

	ret = spi_hid_assert_reset(shid);
	if (ret) {
		dev_err(dev, "%s: failed to assert reset\n", __func__);
		goto err0;
	}

	shid->power_state = SPI_HID_POWER_MODE_ACTIVE;
	if (!shid->irq_enabled) {
		enable_irq(spi->irq);
		shid->irq_enabled = true;
	} else {
		dev_err(dev, "%s called with interrupt already enabled\n",
								__func__);
		shid->logic_error_count++;
		shid->logic_last_error = -EEXIST;
	}

	ret = spi_hid_power_up(shid);
	if (ret) {
		dev_err(dev, "%s: could not power up\n", __func__);
		goto err1;
	}

	ret = spi_hid_deassert_reset(shid);
	if (ret) {
		dev_err(dev, "%s: failed to deassert reset\n", __func__);
		goto err2;
	}

	dev_err(dev, "%s: %s -> %s\n", __func__,
			spi_hid_power_mode_string(prev_state),
			spi_hid_power_mode_string(shid->power_state));

	return 0;

err2:
	spi_hid_power_down(shid);

err1:
	shid->power_state = SPI_HID_POWER_MODE_OFF;
	pinctrl_select_state(shid->pinctrl, shid->pinctrl_sleep);

err0:
	return ret;
}

static void spi_hid_ll_close(struct hid_device *hid)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	u8 prev_state = shid->power_state;
	int ret;

	if (shid->refresh_in_progress || prev_state == SPI_HID_POWER_MODE_OFF)
		return;

	if (shid->irq_enabled) {
		disable_irq(shid->spi->irq);
		shid->irq_enabled = false;
	} else {
		dev_err(dev, "%s called with interrupt already disabled\n",
								__func__);
		shid->logic_error_count++;
		shid->logic_last_error = -ENOEXEC;
	}
	shid->ready = false;
	sysfs_notify(&dev->kobj, NULL, "ready");
	shid->attempts = 0;
	ret = spi_hid_power_down(shid);
	if (ret) {
		dev_err(dev, "%s: could not power down\n", __func__);
		return;
	}

	shid->power_state = SPI_HID_POWER_MODE_OFF;
	dev_err(dev, "%s: %s -> %s\n", __func__,
			spi_hid_power_mode_string(prev_state),
			spi_hid_power_mode_string(shid->power_state));
}

static int spi_hid_ll_power(struct hid_device *hid, int level)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	int ret = 0;

	mutex_lock(&shid->lock);
	if (!shid->hid)
		ret = -ENODEV;
	mutex_unlock(&shid->lock);

	return ret;
}

static int spi_hid_ll_parse(struct hid_device *hid)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	int ret, len;

	mutex_lock(&shid->lock);

	len = spi_hid_report_descriptor_request(shid);
	if (len < 0) {
		dev_err(dev, "Report descriptor request failed, %d\n", len);
		ret = len;
		goto out;
	}

	/*
	* TODO: below call returning 0 doesn't mean that the report descriptor
	* is good. We might be caching a crc32 of a corrupted r. d. or who
	* knows what the FW sent. Need to have a feedback loop about r. d.
	* being ok and only then cache it.
	*/
	ret = hid_parse_report(hid, (__u8 *) shid->response.content, len);
	if (ret)
		dev_err(dev, "failed parsing report: %d\n", ret);
	else
		shid->report_descriptor_crc32 = crc32_le(0,
					(unsigned char const *)  shid->response.content,
					len);

out:
	mutex_unlock(&shid->lock);

	return ret;
}

static int spi_hid_ll_raw_request(struct hid_device *hid,
		unsigned char reportnum, __u8 *buf, size_t len,
		unsigned char rtype, int reqtype)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	int ret;

	if (!shid->ready) {
		dev_err(&shid->spi->dev, "%s called in unready state\n", __func__);
		return -ENODEV;
	}

	mutex_lock(&shid->lock);

	switch (reqtype) {
	case HID_REQ_SET_REPORT:
		if (buf[0] != reportnum) {
			dev_err(dev, "report id mismatch\n");
			ret = -EINVAL;
			break;
		}

		ret = spi_hid_set_request(shid, &buf[1], len-1,
				reportnum);
		if (ret) {
			dev_err(dev, "failed to set report\n");
			break;
		}

		ret = len;
		break;
	case HID_REQ_GET_REPORT:
		ret = spi_hid_get_request(shid, reportnum);
		if (ret) {
			dev_err(dev, "failed to get report\n");
			break;
		}

		ret = min_t(size_t, len,
			(shid->response.body[0] | (shid->response.body[1] << 8)) - 3);
		memcpy(buf, &shid->response.content, ret);
		break;
	default:
		dev_err(dev, "invalid request type\n");
		ret = -EIO;
	}

	mutex_unlock(&shid->lock);

	return ret;
}

static int spi_hid_ll_output_report(struct hid_device *hid,
		__u8 *buf, size_t len)
{
	int ret;
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	struct spi_hid_output_report report = {
		.content_type = SPI_HID_CONTENT_TYPE_OUTPUT_REPORT,
		.content_length = len - 1 + 3,
		.content_id = buf[0],
		.content = &buf[1],
	};

	mutex_lock(&shid->lock);
	if (!shid->ready) {
		dev_err(dev, "%s called in unready state\n", __func__);
		ret = -ENODEV;
		goto out;
	}

	ret = spi_hid_send_output_report(shid, shid->desc.output_register, &report);
	if (ret)
		dev_err(dev, "failed to send output report\n");

out:
	mutex_unlock(&shid->lock);

	if (ret > 0)
		return -ret;

	if (ret < 0)
		return ret;

	return len;
}

static struct hid_ll_driver spi_hid_ll_driver = {
	.start = spi_hid_ll_start,
	.stop = spi_hid_ll_stop,
	.open = spi_hid_ll_open,
	.close = spi_hid_ll_close,
	.power = spi_hid_ll_power,
	.parse = spi_hid_ll_parse,
	.output_report = spi_hid_ll_output_report,
	.raw_request = spi_hid_ll_raw_request,
};

static const struct of_device_id spi_hid_of_match[] = {
	{ .compatible = "hid-over-spi" },
	{},
};
MODULE_DEVICE_TABLE(of, spi_hid_of_match);

static ssize_t ready_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct spi_hid *shid = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%s\n",
			shid->ready ? "ready" : "not ready");
}
static DEVICE_ATTR_RO(ready);

static ssize_t bus_error_count_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct spi_hid *shid = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d (%d)\n",
			shid->bus_error_count, shid->bus_last_error);
}
static DEVICE_ATTR_RO(bus_error_count);

static ssize_t regulator_error_count_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct spi_hid *shid = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d (%d)\n",
			shid->regulator_error_count,
			shid->regulator_last_error);
}
static DEVICE_ATTR_RO(regulator_error_count);

static ssize_t device_initiated_reset_count_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct spi_hid *shid = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", shid->dir_count);
}
static DEVICE_ATTR_RO(device_initiated_reset_count);

static ssize_t logic_error_count_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct spi_hid *shid = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%d (%d)\n",
			shid->logic_error_count, shid->logic_last_error);
}
static DEVICE_ATTR_RO(logic_error_count);

static const struct attribute *const spi_hid_attributes[] = {
	&dev_attr_ready.attr,
	&dev_attr_bus_error_count.attr,
	&dev_attr_regulator_error_count.attr,
	&dev_attr_device_initiated_reset_count.attr,
	&dev_attr_logic_error_count.attr,
	NULL	/* Terminator */
};

static int spi_hid_probe(struct spi_device *spi)
{
	struct device *dev = &spi->dev;
	struct spi_hid *shid;
	unsigned long irqflags;
	int ret;
	u32 val;

	if (spi->irq <= 0) {
		dev_err(dev, "Missing IRQ\n");
		ret = spi->irq ?: -EINVAL;
		goto err0;
	}

	shid = devm_kzalloc(dev, sizeof(struct spi_hid), GFP_KERNEL);
	if (!shid) {
		ret = -ENOMEM;
		goto err0;
	}

	shid->spi = spi;
	shid->power_state = SPI_HID_POWER_MODE_ACTIVE;
	spi_set_drvdata(spi, shid);

	ret = sysfs_create_files(&dev->kobj, spi_hid_attributes);
	if (ret) {
		dev_err(dev, "Unable to create sysfs attributes\n");
		goto err0;
	}

	ret = device_property_read_u32(dev, "hid-descr-addr", &val);
	if (ret) {
		dev_err(dev, "HID descriptor register address not provided\n");
		ret = -ENODEV;
		goto err1;
	}
	shid->device_descriptor_register = val;

	/*
	* input_register is used for read approval. Set to default value here.
	* It will be overwritten later with value from device descriptor
	*/
	shid->desc.input_register = SPI_HID_DEFAULT_INPUT_REGISTER;

	mutex_init(&shid->lock);
	init_completion(&shid->output_done);

	shid->supply = devm_regulator_get(dev, "vdd");
	if (IS_ERR(shid->supply)) {
		if (PTR_ERR(shid->supply) != -EPROBE_DEFER)
			dev_err(dev, "Failed to get regulator: %ld\n",
					PTR_ERR(shid->supply));
		ret = PTR_ERR(shid->supply);
		goto err1;
	}

	shid->pinctrl = devm_pinctrl_get(dev);
	if (IS_ERR(shid->pinctrl)) {
		dev_err(dev, "Could not get pinctrl handle: %ld\n",
				PTR_ERR(shid->pinctrl));
		ret = PTR_ERR(shid->pinctrl);
		goto err1;
	}

	shid->pinctrl_reset = pinctrl_lookup_state(shid->pinctrl, "reset");
	if (IS_ERR(shid->pinctrl_reset)) {
		dev_err(dev, "Could not get pinctrl reset: %ld\n",
				PTR_ERR(shid->pinctrl_reset));
		ret = PTR_ERR(shid->pinctrl_reset);
		goto err1;
	}

	shid->pinctrl_active = pinctrl_lookup_state(shid->pinctrl, "active");
	if (IS_ERR(shid->pinctrl_active)) {
		dev_err(dev, "Could not get pinctrl active: %ld\n",
				PTR_ERR(shid->pinctrl_active));
		 ret = PTR_ERR(shid->pinctrl_active);
		 goto err1;
	}

	shid->pinctrl_sleep = pinctrl_lookup_state(shid->pinctrl, "sleep");
	if (IS_ERR(shid->pinctrl_sleep)) {
		dev_err(dev, "Could not get pinctrl sleep: %ld\n",
				PTR_ERR(shid->pinctrl_sleep));
		ret = PTR_ERR(shid->pinctrl_sleep);
		goto err1;
	}

	ret = pinctrl_select_state(shid->pinctrl, shid->pinctrl_sleep);
	if (ret) {
		dev_err(dev, "Could not select sleep state\n");
		goto err1;
	}

	msleep(100);

	shid->hid_desc_addr = shid->device_descriptor_register;

	spin_lock_init(&shid->input_lock);
	INIT_WORK(&shid->reset_work, spi_hid_reset_work);
	INIT_WORK(&shid->create_device_work, spi_hid_create_device_work);
	INIT_WORK(&shid->refresh_device_work, spi_hid_refresh_device_work);
	INIT_WORK(&shid->error_work, spi_hid_error_work);

	irqflags = irq_get_trigger_type(spi->irq) | IRQF_ONESHOT;
	ret = request_irq(spi->irq, spi_hid_dev_irq, irqflags,
			dev_name(&spi->dev), shid);
	if (ret)
		goto err1;
	else
		shid->irq_enabled = true;

	ret = spi_hid_assert_reset(shid);
	if (ret) {
		dev_err(dev, "%s: failed to assert reset\n", __func__);
		goto err1;
	}

	ret = spi_hid_power_up(shid);
	if (ret) {
		dev_err(dev, "%s: could not power up\n", __func__);
		goto err1;
	}

	ret = spi_hid_deassert_reset(shid);
	if (ret) {
		dev_err(dev, "%s: failed to deassert reset\n", __func__);
		goto err1;
	}

	dev_err(dev, "%s: d3 -> %s\n", __func__,
			spi_hid_power_mode_string(shid->power_state));

	return 0;

err1:
	sysfs_remove_files(&dev->kobj, spi_hid_attributes);

err0:
	return ret;
}

static void spi_hid_remove(struct spi_device *spi)
{
	struct spi_hid *shid = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;

	dev_info(dev, "%s\n", __func__);

	spi_hid_power_down(shid);
	free_irq(spi->irq, shid);
	shid->irq_enabled = false;
	sysfs_remove_files(&dev->kobj, spi_hid_attributes);
	spi_hid_stop_hid(shid);
}

static const struct spi_device_id spi_hid_id_table[] = {
	{ "hid", 0 },
	{ "hid-over-spi", 0 },
	{ },
};
MODULE_DEVICE_TABLE(spi, spi_hid_id_table);

static struct spi_driver spi_hid_driver = {
	.driver = {
		.name	= "spi_hid",
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
