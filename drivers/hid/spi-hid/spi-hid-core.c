// SPDX-License-Identifier: GPL-2.0
/*
 * HID over SPI protocol implementation
 *
 * Copyright (c) 2021 Microsoft Corporation
 * Copyright (c) 2026 Google LLC
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
 */

#include <linux/cache.h>
#include <linux/completion.h>
#include <linux/crc32.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/hid.h>
#include <linux/hid-over-spi.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pm.h>
#include <linux/pm_wakeirq.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/unaligned.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "spi-hid.h"
#include "spi-hid-core.h"

#define CREATE_TRACE_POINTS
#include "spi-hid-trace.h"

/* Protocol constants */
#define SPI_HID_READ_APPROVAL_CONSTANT		0xff
#define SPI_HID_INPUT_HEADER_SYNC_BYTE		0x5a
#define SPI_HID_INPUT_HEADER_VERSION		0x03
#define SPI_HID_SUPPORTED_VERSION		0x0300

#define SPI_HID_OUTPUT_REPORT_CONTENT_ID_DESC_REQUEST	0x00

#define SPI_HID_MAX_RESET_ATTEMPTS	3
#define SPI_HID_RESP_TIMEOUT		1000

/* Protocol message size constants */
#define SPI_HID_READ_APPROVAL_LEN		5
#define SPI_HID_OUTPUT_HEADER_LEN		8

/* flags */
/*
 * ready flag indicates that the FW is ready to accept commands and
 * requests. The FW becomes ready after sending the report descriptor.
 */
#define SPI_HID_READY	0
/*
 * refresh_in_progress is set to true while the refresh_device worker
 * thread is destroying and recreating the hidraw device. When this flag
 * is set to true, the ll_close and ll_open functions will not cause
 * power state changes.
 */
#define SPI_HID_REFRESH_IN_PROGRESS	1
/*
 * reset_pending indicates that the device is being reset. When this flag
 * is set to true, garbage interrupts triggered during reset will be
 * dropped and will not cause error handling.
 */
#define SPI_HID_RESET_PENDING	2
#define SPI_HID_RESET_RESPONSE	3
#define SPI_HID_CREATE_DEVICE	4
#define SPI_HID_ERROR	5

/* Processed data from input report header */
struct spi_hid_input_header {
	u8 version;
	u16 report_length;
	u8 last_fragment_flag;
	u8 sync_const;
};

/* Processed data from an input report */
struct spi_hid_input_report {
	u8 report_type;
	u16 content_length;
	u8 content_id;
	u8 *content;
};

/* Data necessary to send an output report */
struct spi_hid_output_report {
	u8 report_type;
	u16 content_length;
	u8 content_id;
	u8 *content;
};

static struct hid_ll_driver spi_hid_ll_driver;

static void spi_hid_populate_read_approvals(const struct spi_hid_conf *conf,
					    u8 *header_buf, u8 *body_buf)
{
	header_buf[0] = conf->read_opcode;
	put_unaligned_be24(conf->input_report_header_address, &header_buf[1]);
	header_buf[4] = SPI_HID_READ_APPROVAL_CONSTANT;

	body_buf[0] = conf->read_opcode;
	put_unaligned_be24(conf->input_report_body_address, &body_buf[1]);
	body_buf[4] = SPI_HID_READ_APPROVAL_CONSTANT;
}

static void spi_hid_parse_dev_desc(const struct hidspi_dev_descriptor *raw,
				   struct spi_hid_device_descriptor *desc)
{
	desc->hid_version = le16_to_cpu(raw->bcd_ver);
	desc->report_descriptor_length = le16_to_cpu(raw->rep_desc_len);
	desc->max_input_length = le16_to_cpu(raw->max_input_len);
	desc->max_output_length = le16_to_cpu(raw->max_output_len);

	/* FIXME: multi-fragment not supported, field below not used */
	desc->max_fragment_length = le16_to_cpu(raw->max_frag_len);

	desc->vendor_id = le16_to_cpu(raw->vendor_id);
	desc->product_id = le16_to_cpu(raw->product_id);
	desc->version_id = le16_to_cpu(raw->version_id);
	desc->no_output_report_ack = le16_to_cpu(raw->flags) & BIT(0);
}

static void spi_hid_populate_input_header(const u8 *buf,
					  struct spi_hid_input_header *header)
{
	header->version            = buf[0] & 0xf;
	header->report_length      = (get_unaligned_le16(&buf[1]) & 0x3fff) * 4;
	header->last_fragment_flag = (buf[2] & 0x40) >> 6;
	header->sync_const         = buf[3];
}

static void spi_hid_populate_input_body(const u8 *buf,
					struct input_report_body_header *body)
{
	body->input_report_type = buf[0];
	body->content_len = get_unaligned_le16(&buf[1]);
	body->content_id = buf[3];
}

static void spi_hid_input_report_prepare(struct spi_hid_input_buf *buf,
					 struct spi_hid_input_report *report)
{
	struct spi_hid_input_header header;
	struct input_report_body_header body;

	spi_hid_populate_input_header(buf->header, &header);
	spi_hid_populate_input_body(buf->body, &body);
	report->report_type = body.input_report_type;
	report->content_length = body.content_len;
	report->content_id = body.content_id;
	report->content = buf->content;
}

static void spi_hid_populate_output_header(u8 *buf,
					   const struct spi_hid_conf *conf,
					   const struct spi_hid_output_report *report)
{
	buf[0] = conf->write_opcode;
	put_unaligned_be24(conf->output_report_address, &buf[1]);
	buf[4] = report->report_type;
	put_unaligned_le16(report->content_length, &buf[5]);
	buf[7] = report->content_id;
}

static int spi_hid_input_sync(struct spi_hid *shid, void *buf, u16 length,
			      bool is_header)
{
	int error;

	shid->input_transfer[0].tx_buf = is_header ?
					 shid->read_approval_header :
					 shid->read_approval_body;
	shid->input_transfer[0].len = SPI_HID_READ_APPROVAL_LEN;

	shid->input_transfer[1].rx_buf = buf;
	shid->input_transfer[1].len = length;

	spi_message_init_with_transfers(&shid->input_message,
					shid->input_transfer, 2);

	trace_spi_hid_input_sync(shid,	shid->input_transfer[0].tx_buf,
				 shid->input_transfer[0].len,
				 shid->input_transfer[1].rx_buf,
				 shid->input_transfer[1].len, 0);

	error = spi_sync(shid->spi, &shid->input_message);
	if (error) {
		dev_err(&shid->spi->dev, "Error starting sync transfer: %d\n", error);
		shid->bus_error_count++;
		shid->bus_last_error = error;
		return error;
	}

	return 0;
}

static int spi_hid_output(struct spi_hid *shid, const void *buf, u16 length)
{
	int error;

	error = spi_write(shid->spi, buf, length);

	if (error) {
		shid->bus_error_count++;
		shid->bus_last_error = error;
	}

	return error;
}

static const char *spi_hid_power_mode_string(enum hidspi_power_state power_state)
{
	switch (power_state) {
	case HIDSPI_ON:
		return "d0";
	case HIDSPI_SLEEP:
		return "d2";
	case HIDSPI_OFF:
		return "d3";
	default:
		return "unknown";
	}
}

static int spi_hid_suspend(struct spi_hid *shid)
{
	int error;
	struct device *dev = &shid->spi->dev;

	guard(mutex)(&shid->power_lock);
	if (shid->power_state == HIDSPI_OFF)
		return 0;

	if (shid->hid) {
		error = hid_driver_suspend(shid->hid, PMSG_SUSPEND);
		if (error) {
			dev_err(dev, "%s failed to suspend hid driver: %d\n",
				__func__, error);
			return error;
		}
	}

	disable_irq(shid->spi->irq);

	if (!device_may_wakeup(dev)) {
		set_bit(SPI_HID_RESET_PENDING, &shid->flags);

		shid->ops->assert_reset(shid->ops);

		error = shid->ops->power_down(shid->ops);
		if (error) {
			dev_err(dev, "%s: could not power down\n", __func__);
			shid->regulator_error_count++;
			shid->regulator_last_error = error;
			/* Undo partial suspend before returning error */
			shid->ops->deassert_reset(shid->ops);
			clear_bit(SPI_HID_RESET_PENDING, &shid->flags);
			enable_irq(shid->spi->irq);
			if (shid->hid)
				hid_driver_reset_resume(shid->hid);
			return error;
		}

		shid->power_state = HIDSPI_OFF;
	}
	return 0;
}

static int spi_hid_resume(struct spi_hid *shid)
{
	int error;
	struct device *dev = &shid->spi->dev;

	guard(mutex)(&shid->power_lock);

	if (!device_may_wakeup(dev)) {
		if (shid->power_state == HIDSPI_OFF) {
			shid->ops->assert_reset(shid->ops);

			shid->ops->sleep_minimal_reset_delay(shid->ops);

			error = shid->ops->power_up(shid->ops);
			if (error) {
				dev_err(dev, "%s: could not power up\n", __func__);
				shid->regulator_error_count++;
				shid->regulator_last_error = error;
				return error;
			}
			shid->power_state = HIDSPI_ON;
			shid->ops->deassert_reset(shid->ops);
		}
	}

	enable_irq(shid->spi->irq);

	if (shid->hid) {
		error = hid_driver_reset_resume(shid->hid);
		if (error) {
			dev_err(dev, "%s: failed to reset resume hid driver: %d\n",
				__func__, error);
			/* Undo partial resume before returning error */
			disable_irq(shid->spi->irq);
			if (!device_may_wakeup(dev)) {
				set_bit(SPI_HID_RESET_PENDING, &shid->flags);
				shid->ops->assert_reset(shid->ops);
				shid->ops->power_down(shid->ops);
				shid->power_state = HIDSPI_OFF;
			}
			return error;
		}
	}
	return 0;
}

static void spi_hid_stop_hid(struct spi_hid *shid)
{
	struct hid_device *hid;

	scoped_guard(mutex, &shid->io_lock) {
		hid = shid->hid;
		shid->hid = NULL;
		clear_bit(SPI_HID_READY, &shid->flags);
	}

	if (hid)
		hid_destroy_device(hid);
}

static void spi_hid_error_handler(struct spi_hid *shid)
{
	struct device *dev = &shid->spi->dev;
	int error;

	trace_spi_hid_error_handler(shid);

	guard(mutex)(&shid->power_lock);
	if (shid->power_state == HIDSPI_OFF)
		return;

	guard(disable_irq)(&shid->spi->irq);

	if (shid->reset_attempts++ >= SPI_HID_MAX_RESET_ATTEMPTS) {
		dev_err(dev, "unresponsive device, aborting\n");
		spi_hid_stop_hid(shid);
		shid->ops->assert_reset(shid->ops);
		error = shid->ops->power_down(shid->ops);
		if (error) {
			dev_err(dev, "failed to disable regulator\n");
			shid->regulator_error_count++;
			shid->regulator_last_error = error;
		}
		return;
	}

	clear_bit(SPI_HID_READY, &shid->flags);
	set_bit(SPI_HID_RESET_PENDING, &shid->flags);

	shid->ops->assert_reset(shid->ops);

	shid->power_state = HIDSPI_OFF;

	/*
	 * We want to cancel pending reset work as the device is being reset
	 * to recover from an error. cancel_work_sync will put us in a deadlock
	 * because this function is scheduled in 'reset_work' and we should
	 * avoid waiting for itself.
	 */
	cancel_work(&shid->reset_work);

	shid->ops->sleep_minimal_reset_delay(shid->ops);

	shid->power_state = HIDSPI_ON;

	shid->ops->deassert_reset(shid->ops);
}

static int __spi_hid_send_output_report(struct spi_hid *shid,
					struct spi_hid_output_report *report)
{
	struct spi_hid_output_buf *buf = shid->output;
	struct device *dev = &shid->spi->dev;
	u16 report_length;
	u16 padded_length;
	u8 padding;
	int error;

	if (report->content_length > shid->desc.max_output_length ||
	    report->content_length > shid->bufsize) {
		dev_err(dev, "Output report too big, content_length 0x%x\n",
			report->content_length);
		return -E2BIG;
	}

	guard(mutex)(&shid->io_lock);
	spi_hid_populate_output_header(buf->header, shid->conf, report);

	if (report->content_length)
		memcpy(&buf->content, report->content, report->content_length);

	report_length = sizeof(buf->header) + report->content_length;
	padded_length = round_up(report_length, 4);
	padding = padded_length - report_length;
	memset(&buf->content[report->content_length], 0, padding);

	error = spi_hid_output(shid, buf, padded_length);
	if (error)
		dev_err(dev, "Failed output transfer: %d\n", error);

	return error;
}

static int spi_hid_send_output_report(struct spi_hid *shid,
				      struct spi_hid_output_report *report)
{
	guard(mutex)(&shid->output_lock);
	return __spi_hid_send_output_report(shid, report);
}

static int spi_hid_sync_request(struct spi_hid *shid,
				struct spi_hid_output_report *report)
{
	struct device *dev = &shid->spi->dev;
	int error;

	guard(mutex)(&shid->output_lock);

	reinit_completion(&shid->output_done);

	error = __spi_hid_send_output_report(shid, report);
	if (error)
		return error;

	error = wait_for_completion_interruptible_timeout(&shid->output_done,
							  msecs_to_jiffies(SPI_HID_RESP_TIMEOUT));
	if (error == 0) {
		dev_err(dev, "Response timed out\n");
		return -ETIMEDOUT;
	}
	if (error < 0)
		return error;

	return 0;
}

/*
 * Handle the reset response from the FW by sending a request for the device
 * descriptor.
 */
static void spi_hid_reset_response(struct spi_hid *shid)
{
	struct device *dev = &shid->spi->dev;
	struct spi_hid_output_report report = {
		.report_type = DEVICE_DESCRIPTOR,
		.content_length = 0x0,
		.content_id = SPI_HID_OUTPUT_REPORT_CONTENT_ID_DESC_REQUEST,
		.content = NULL,
	};
	int error;

	trace_spi_hid_reset_response(shid);

	if (test_bit(SPI_HID_READY, &shid->flags)) {
		dev_err(dev, "Spontaneous FW reset!\n");
		clear_bit(SPI_HID_READY, &shid->flags);
		shid->dir_count++;
	}

	if (shid->power_state == HIDSPI_OFF)
		return;

	error = spi_hid_sync_request(shid, &report);
	if (error) {
		dev_WARN_ONCE(dev, true,
			      "Failed to send device descriptor request: %d\n", error);
		set_bit(SPI_HID_ERROR, &shid->flags);
		schedule_work(&shid->reset_work);
	}
}

static int spi_hid_input_report_handler(struct spi_hid *shid,
					struct spi_hid_input_buf *buf)
{
	struct device *dev = &shid->spi->dev;
	struct spi_hid_input_report r;
	int error = 0;

	guard(mutex)(&shid->io_lock);
	trace_spi_hid_input_report_handler(shid);

	if (!test_bit(SPI_HID_READY, &shid->flags) ||
	    test_bit(SPI_HID_REFRESH_IN_PROGRESS, &shid->flags) || !shid->hid) {
		dev_err(dev, "HID not ready\n");
		return 0;
	}

	spi_hid_input_report_prepare(buf, &r);

	error = hid_input_report(shid->hid, HID_INPUT_REPORT,
				 r.content - 1, r.content_length + 1, 1);

	if (error == -ENODEV || error == -EBUSY) {
		dev_err(dev, "ignoring report --> %d\n", error);
		return 0;
	} else if (error) {
		dev_err(dev, "Bad input report: %d\n", error);
	}

	return error;
}

static void spi_hid_response_handler(struct spi_hid *shid,
				     struct input_report_body_header *body)
{
	trace_spi_hid_response_handler(shid);

	shid->response_length = body->content_len;
	/* completion_done returns 0 if there are waiters, otherwise 1 */
	if (completion_done(&shid->output_done)) {
		dev_err(&shid->spi->dev, "Unexpected response report\n");
	} else {
		if (body->input_report_type == REPORT_DESCRIPTOR_RESPONSE ||
		    body->input_report_type == GET_FEATURE_RESPONSE) {
			memcpy(shid->response->body, shid->input->body,
			       sizeof(shid->input->body));
			memcpy(shid->response->content, shid->input->content,
			       body->content_len);
		}
		complete(&shid->output_done);
	}
}

/*
 * This function returns the length of the report descriptor, or a negative
 * error code if something went wrong.
 */
static int spi_hid_report_descriptor_request(struct spi_hid *shid)
{
	struct device *dev = &shid->spi->dev;
	struct spi_hid_output_report report = {
		.report_type = REPORT_DESCRIPTOR,
		.content_length = 0,
		.content_id = SPI_HID_OUTPUT_REPORT_CONTENT_ID_DESC_REQUEST,
		.content = NULL,
	};
	int ret;

	ret =  spi_hid_sync_request(shid, &report);
	if (ret) {
		dev_err(dev,
			"Expected report descriptor not received: %d\n", ret);
		set_bit(SPI_HID_ERROR, &shid->flags);
		schedule_work(&shid->reset_work);
		return ret;
	}

	ret = shid->response_length;
	if (ret != shid->desc.report_descriptor_length) {
		ret = min_t(unsigned int, ret, shid->desc.report_descriptor_length);
		dev_err(dev, "Received report descriptor length doesn't match device descriptor field, using min of the two: %d\n",
			ret);
	}

	return ret;
}

static int spi_hid_create_device(struct spi_hid *shid)
{
	struct hid_device *hid;
	struct device *dev = &shid->spi->dev;
	int error;

	trace_spi_hid_create_device(shid);

	hid = hid_allocate_device();
	error = PTR_ERR_OR_ZERO(hid);
	if (error) {
		dev_err(dev, "Failed to allocate hid device: %d\n", error);
		return error;
	}

	hid->driver_data = shid->spi;
	hid->ll_driver = &spi_hid_ll_driver;
	hid->dev.parent = &shid->spi->dev;
	hid->bus = BUS_SPI;
	hid->version = shid->desc.hid_version;
	hid->vendor = shid->desc.vendor_id;
	hid->product = shid->desc.product_id;

	snprintf(hid->name, sizeof(hid->name), "spi %04X:%04X",
		 hid->vendor, hid->product);
	strscpy(hid->phys, dev_name(&shid->spi->dev), sizeof(hid->phys));

	scoped_guard(mutex, &shid->io_lock) {
		shid->hid = hid;
	}

	error = hid_add_device(hid);
	if (error) {
		dev_err(dev, "Failed to add hid device: %d\n", error);
		/*
		 * We likely got here because report descriptor request timed
		 * out. Let's disconnect and destroy the hid_device structure.
		 */
		spi_hid_stop_hid(shid);
		return error;
	}

	return 0;
}

static void spi_hid_refresh_device(struct spi_hid *shid)
{
	struct device *dev = &shid->spi->dev;
	u32 new_crc32 = 0;
	int error = 0;

	trace_spi_hid_refresh_device(shid);

	error = spi_hid_report_descriptor_request(shid);
	if (error < 0) {
		dev_err(dev,
			"%s: failed report descriptor request: %d\n",
			__func__, error);
		return;
	}
	new_crc32 = crc32_le(0, (unsigned char const *)shid->response->content,
			     (size_t)error);

	/* Same report descriptor, so no need to create a new hid device. */
	if (new_crc32 == shid->report_descriptor_crc32) {
		set_bit(SPI_HID_READY, &shid->flags);
		return;
	}

	shid->report_descriptor_crc32 = new_crc32;

	set_bit(SPI_HID_REFRESH_IN_PROGRESS, &shid->flags);

	spi_hid_stop_hid(shid);

	error = spi_hid_create_device(shid);
	if (error) {
		dev_err(dev, "%s: Failed to create hid device: %d\n", __func__, error);
		return;
	}

	clear_bit(SPI_HID_REFRESH_IN_PROGRESS, &shid->flags);
}

static void spi_hid_reset_work(struct work_struct *work)
{
	struct spi_hid *shid =
		container_of(work, struct spi_hid, reset_work);
	struct device *dev = &shid->spi->dev;
	int error = 0;
	bool resched = false;

	if (test_and_clear_bit(SPI_HID_RESET_RESPONSE, &shid->flags)) {
		spi_hid_reset_response(shid);
		resched = true;
	} else if (test_and_clear_bit(SPI_HID_CREATE_DEVICE, &shid->flags)) {
		guard(mutex)(&shid->power_lock);
		if (shid->power_state != HIDSPI_OFF) {
			if (!shid->hid) {
				error = spi_hid_create_device(shid);
				if (error) {
					dev_err(dev, "%s: Failed to create hid device: %d\n",
						__func__, error);
				}
			} else {
				spi_hid_refresh_device(shid);
			}
		} else {
			dev_err(dev, "%s: Powered off, returning\n", __func__);
		}
		resched = true;
	} else if (test_and_clear_bit(SPI_HID_ERROR, &shid->flags)) {
		spi_hid_error_handler(shid);
	}

	/*
	 * If other flags are still pending, safely reschedule ourselves
	 * to process them in the next workqueue cycle.
	 */
	if (resched && (shid->flags & (BIT(SPI_HID_RESET_RESPONSE) |
				       BIT(SPI_HID_CREATE_DEVICE) |
				       BIT(SPI_HID_ERROR)))) {
		schedule_work(&shid->reset_work);
	}
}

static int spi_hid_process_input_report(struct spi_hid *shid,
					struct spi_hid_input_buf *buf)
{
	struct spi_hid_input_header header;
	struct input_report_body_header body;
	struct device *dev = &shid->spi->dev;
	struct hidspi_dev_descriptor *raw;

	trace_spi_hid_process_input_report(shid);

	spi_hid_populate_input_header(buf->header, &header);
	spi_hid_populate_input_body(buf->body, &body);

	if (HIDSPI_INPUT_BODY_SIZE(body.content_len) > header.report_length) {
		dev_err(dev, "Bad body length %zu > %u\n", HIDSPI_INPUT_BODY_SIZE(body.content_len),
			header.report_length);
		return -EPROTO;
	}

	switch (body.input_report_type) {
	case DATA:
		return spi_hid_input_report_handler(shid, buf);
	case RESET_RESPONSE:
		clear_bit(SPI_HID_RESET_PENDING, &shid->flags);
		set_bit(SPI_HID_RESET_RESPONSE, &shid->flags);
		schedule_work(&shid->reset_work);
		break;
	case DEVICE_DESCRIPTOR_RESPONSE:
		/* Mark the completion done to avoid timeout */
		spi_hid_response_handler(shid, &body);

		/* Reset attempts at every device descriptor fetch */
		shid->reset_attempts = 0;
		raw = (struct hidspi_dev_descriptor *)buf->content;

		/* Validate device descriptor length before parsing */
		if (body.content_len != HIDSPI_DEVICE_DESCRIPTOR_SIZE) {
			dev_err(dev, "Invalid content length %d, expected %zu\n",
				body.content_len,
				HIDSPI_DEVICE_DESCRIPTOR_SIZE);
			return -EPROTO;
		}

		if (le16_to_cpu(raw->dev_desc_len) !=
		    HIDSPI_DEVICE_DESCRIPTOR_SIZE) {
			dev_err(dev,
				"Invalid wDeviceDescLength %d, expected %zu\n",
				le16_to_cpu(raw->dev_desc_len),
				HIDSPI_DEVICE_DESCRIPTOR_SIZE);
			return -EPROTO;
		}

		spi_hid_parse_dev_desc(raw, &shid->desc);

		if (shid->desc.hid_version != SPI_HID_SUPPORTED_VERSION) {
			dev_err(dev,
				"Unsupported device descriptor version %4x\n",
				shid->desc.hid_version);
			return -EPROTONOSUPPORT;
		}

		set_bit(SPI_HID_CREATE_DEVICE, &shid->flags);
		schedule_work(&shid->reset_work);

		break;
	case OUTPUT_REPORT_RESPONSE:
		if (shid->desc.no_output_report_ack) {
			dev_err(dev, "Unexpected output report response\n");
			break;
		}
		fallthrough;
	case GET_FEATURE_RESPONSE:
	case SET_FEATURE_RESPONSE:
	case REPORT_DESCRIPTOR_RESPONSE:
		spi_hid_response_handler(shid, &body);
		break;
	/*
	 * FIXME: sending GET_INPUT and COMMAND reports not supported, thus
	 * throw away responses to those, they should never come.
	 */
	case GET_INPUT_REPORT_RESPONSE:
	case COMMAND_RESPONSE:
		dev_err(dev, "Not a supported report type: 0x%x\n",
			body.input_report_type);
		break;
	default:
		dev_err(dev, "Unknown input report: 0x%x\n", body.input_report_type);
		return -EPROTO;
	}

	return 0;
}

static int spi_hid_bus_validate_header(struct spi_hid *shid,
				       struct spi_hid_input_header *header)
{
	struct device *dev = &shid->spi->dev;

	if (header->version != SPI_HID_INPUT_HEADER_VERSION) {
		dev_err(dev, "Unknown input report version (v 0x%x)\n",
			header->version);
		return -EINVAL;
	}

	if (shid->desc.max_input_length != 0 &&
	    header->report_length > shid->desc.max_input_length) {
		dev_err(dev, "Input report body size %u > max expected of %u\n",
			header->report_length, shid->desc.max_input_length);
		return -EMSGSIZE;
	}

	if (header->last_fragment_flag != 1) {
		dev_err(dev, "Multi-fragment reports not supported\n");
		return -EOPNOTSUPP;
	}

	if (header->sync_const != SPI_HID_INPUT_HEADER_SYNC_BYTE) {
		dev_err(dev, "Invalid input report sync constant (0x%x)\n",
			header->sync_const);
		return -EINVAL;
	}

	return 0;
}

static int spi_hid_get_request(struct spi_hid *shid, u8 content_id)
{
	struct device *dev = &shid->spi->dev;
	struct spi_hid_output_report report = {
		.report_type = GET_FEATURE,
		.content_length = 0,
		.content_id = content_id,
		.content = NULL,
	};
	int error;

	error = spi_hid_sync_request(shid, &report);
	if (error) {
		dev_err(dev,
			"Expected get request response not received! Error %d\n",
			error);
		set_bit(SPI_HID_ERROR, &shid->flags);
		schedule_work(&shid->reset_work);
		return error;
	}

	return 0;
}

static int spi_hid_set_request(struct spi_hid *shid, u8 *arg_buf, u16 arg_len,
			       u8 content_id)
{
	struct spi_hid_output_report report = {
		.report_type = SET_FEATURE,
		.content_length = arg_len,
		.content_id = content_id,
		.content = arg_buf,
	};

	return spi_hid_sync_request(shid, &report);
}

static irqreturn_t spi_hid_dev_irq(int irq, void *_shid)
{
	struct spi_hid *shid = _shid;
	struct device *dev = &shid->spi->dev;
	struct spi_hid_input_header header;
	int error = 0;

	trace_spi_hid_dev_irq(shid, irq);
	trace_spi_hid_header_transfer(shid);

	scoped_guard(mutex, &shid->io_lock) {
		if (shid->power_state == HIDSPI_OFF) {
			dev_warn(dev, "Device is off, ignoring interrupt\n");
			goto out;
		}

		error = spi_hid_input_sync(shid, shid->input->header,
					   sizeof(shid->input->header), true);
		if (error) {
			dev_err(dev, "Failed to transfer header: %d\n", error);
			goto err;
		}

		trace_spi_hid_input_header_complete(shid,
						    shid->input_transfer[0].tx_buf,
						    shid->input_transfer[0].len,
						    shid->input_transfer[1].rx_buf,
						    shid->input_transfer[1].len,
						    shid->input_message.status);

		if (shid->input_message.status < 0) {
			dev_warn(dev, "Error reading header: %d\n",
				 shid->input_message.status);
			shid->bus_error_count++;
			shid->bus_last_error = shid->input_message.status;
			goto err;
		}

		spi_hid_populate_input_header(shid->input->header, &header);

		error = spi_hid_bus_validate_header(shid, &header);
		if (error) {
			if (!test_bit(SPI_HID_RESET_PENDING, &shid->flags)) {
				dev_err(dev, "Failed to validate header: %d\n", error);
				print_hex_dump(KERN_ERR, "spi_hid: header buffer: ",
					       DUMP_PREFIX_NONE, 16, 1, shid->input->header,
					       sizeof(shid->input->header), false);
				shid->bus_error_count++;
				shid->bus_last_error = error;
				goto err;
			}
			goto out;
		}

		error = spi_hid_input_sync(shid, shid->input->body, header.report_length,
					   false);
		if (error) {
			dev_err(dev, "Failed to transfer body: %d\n", error);
			goto err;
		}

		if (shid->power_state == HIDSPI_OFF) {
			dev_warn(dev, "Device is off after body was received\n");
			goto out;
		}

		trace_spi_hid_input_body_complete(shid, shid->input_transfer[0].tx_buf,
						  shid->input_transfer[0].len,
						  shid->input_transfer[1].rx_buf,
						  shid->input_transfer[1].len,
						  shid->input_message.status);

		if (shid->input_message.status < 0) {
			dev_warn(dev, "Error reading body: %d\n",
				 shid->input_message.status);
			shid->bus_error_count++;
			shid->bus_last_error = shid->input_message.status;
			goto err;
		}
	}

	error = spi_hid_process_input_report(shid, shid->input);
	if (error) {
		dev_err(dev, "Failed to process input report: %d\n", error);
		goto err;
	}

out:
	return IRQ_HANDLED;

err:
	set_bit(SPI_HID_ERROR, &shid->flags);
	schedule_work(&shid->reset_work);
	return IRQ_HANDLED;
}

static int spi_hid_alloc_buffers(struct spi_hid *shid, size_t report_size)
{
	struct device *dev = &shid->spi->dev;
	int inbufsize = round_up(sizeof(shid->input->header) +
				 sizeof(shid->input->body) + report_size, 4);
	int outbufsize = round_up(sizeof(shid->output->header) + report_size, 4);
	void *tmp;

	tmp = devm_krealloc(dev, shid->output, outbufsize, GFP_KERNEL | __GFP_ZERO);
	if (!tmp)
		return -ENOMEM;
	shid->output = tmp;

	tmp = devm_krealloc(dev, shid->input, inbufsize, GFP_KERNEL | __GFP_ZERO);
	if (!tmp)
		return -ENOMEM;
	shid->input = tmp;

	tmp = devm_krealloc(dev, shid->response, inbufsize, GFP_KERNEL | __GFP_ZERO);
	if (!tmp)
		return -ENOMEM;
	shid->response = tmp;

	if (!shid->output || !shid->input || !shid->response)
		return -ENOMEM;

	shid->bufsize = report_size;

	return 0;
}

static int spi_hid_get_report_length(struct hid_report *report)
{
	return DIV_ROUND_UP(report->size, 8) +
		report->device->report_enum[report->type].numbered + 2;
}

/*
 * Traverse the supplied list of reports and find the longest
 */
static void spi_hid_find_max_report(struct hid_device *hid, u32 type,
				    u16 *max)
{
	struct hid_report *report;
	u16 size;

	/*
	 * We should not rely on wMaxInputLength, as some devices may set it to
	 * a wrong length.
	 */
	list_for_each_entry(report, &hid->report_enum[type].report_list, list) {
		size = spi_hid_get_report_length(report);
		if (*max < size)
			*max = size;
	}
}

/* hid_ll_driver interface functions */

static int spi_hid_ll_start(struct hid_device *hid)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	int error = 0;
	u16 bufsize = 0;

	spi_hid_find_max_report(hid, HID_INPUT_REPORT, &bufsize);
	spi_hid_find_max_report(hid, HID_OUTPUT_REPORT, &bufsize);
	spi_hid_find_max_report(hid, HID_FEATURE_REPORT, &bufsize);

	if (bufsize < HID_MIN_BUFFER_SIZE) {
		dev_err(&spi->dev,
			"HID_MIN_BUFFER_SIZE > max_input_length (%d)\n",
			bufsize);
		return -EINVAL;
	}

	if (bufsize > shid->bufsize) {
		guard(disable_irq)(&shid->spi->irq);

		error = spi_hid_alloc_buffers(shid, bufsize);
		if (error)
			return error;
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

	set_bit(SPI_HID_READY, &shid->flags);
	return 0;
}

static void spi_hid_ll_close(struct hid_device *hid)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);

	clear_bit(SPI_HID_READY, &shid->flags);
	shid->reset_attempts = 0;
}

static int spi_hid_ll_power(struct hid_device *hid, int level)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	int error = 0;

	guard(mutex)(&shid->output_lock);
	if (!shid->hid)
		error = -ENODEV;

	return error;
}

static int spi_hid_ll_parse(struct hid_device *hid)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	unsigned int rsize = shid->desc.report_descriptor_length;
	int error, len;

	if (rsize > HID_MAX_DESCRIPTOR_SIZE) {
		dev_err(dev,
			"Report descriptor size %d is greater than HID_MAX_DESCRIPTOR_SIZE %d\n",
			rsize, HID_MAX_DESCRIPTOR_SIZE);
		return -EINVAL;
	}

	if (rsize > shid->bufsize) {
		error = spi_hid_alloc_buffers(shid, rsize);
		if (error)
			return error;
	}

	len = spi_hid_report_descriptor_request(shid);
	if (len < 0) {
		dev_err(dev, "Report descriptor request failed, %d\n", len);
		return len;
	}

	/*
	 * FIXME: below call returning 0 doesn't mean that the report descriptor
	 * is good. We might be caching a crc32 of a corrupted r. d. or who
	 * knows what the FW sent. Need to have a feedback loop about r. d.
	 * being ok and only then cache it.
	 */
	error = hid_parse_report(hid, (u8 *)shid->response->content, len);
	if (error) {
		dev_err(dev, "failed parsing report: %d\n", error);
		return error;
	}
	shid->report_descriptor_crc32 = crc32_le(0,
						 (unsigned char const *)shid->response->content,
						 len);

	return 0;
}

static int spi_hid_ll_raw_request(struct hid_device *hid,
				  unsigned char reportnum, __u8 *buf,
				  size_t len, unsigned char rtype, int reqtype)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	int ret;

	switch (reqtype) {
	case HID_REQ_SET_REPORT:
		if (buf[0] != reportnum) {
			dev_err(dev, "report id mismatch\n");
			return -EINVAL;
		}

		ret = spi_hid_set_request(shid, &buf[1], len - 1,
					  reportnum);
		if (ret) {
			dev_err(dev, "failed to set report\n");
			return ret;
		}

		ret = len;
		break;
	case HID_REQ_GET_REPORT:
		ret = spi_hid_get_request(shid, reportnum);
		if (ret) {
			dev_err(dev, "failed to get report\n");
			return ret;
		}

		ret = min_t(size_t, len,
			    (shid->response->body[1] | (shid->response->body[2] << 8)) + 1);
		buf[0] = shid->response->body[3];
		memcpy(&buf[1], &shid->response->content, ret);
		break;
	default:
		dev_err(dev, "invalid request type\n");
		return -EIO;
	}

	return ret;
}

static int spi_hid_ll_output_report(struct hid_device *hid, __u8 *buf,
				    size_t len)
{
	struct spi_device *spi = hid->driver_data;
	struct spi_hid *shid = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	struct spi_hid_output_report report = {
		.report_type = OUTPUT_REPORT,
		.content_length = len - 1,
		.content_id = buf[0],
		.content = &buf[1],
	};
	int error;

	if (!test_bit(SPI_HID_READY, &shid->flags)) {
		dev_err(dev, "%s called in unready state\n", __func__);
		return -ENODEV;
	}

	if (shid->desc.no_output_report_ack) {
		scoped_guard(mutex, &shid->output_lock) {
			error = spi_hid_send_output_report(shid, &report);
		}
	} else {
		error = spi_hid_sync_request(shid, &report);
	}

	if (error) {
		dev_err(dev, "failed to send output report\n");
		return error;
	}

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

static ssize_t bus_error_count_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct spi_hid *shid = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%u (%d)\n",
			  shid->bus_error_count, shid->bus_last_error);
}
static DEVICE_ATTR_RO(bus_error_count);

static ssize_t regulator_error_count_show(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct spi_hid *shid = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%u (%d)\n",
			  shid->regulator_error_count,
			  shid->regulator_last_error);
}
static DEVICE_ATTR_RO(regulator_error_count);

static ssize_t device_initiated_reset_count_show(struct device *dev,
						 struct device_attribute *attr,
						 char *buf)
{
	struct spi_hid *shid = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%u\n", shid->dir_count);
}
static DEVICE_ATTR_RO(device_initiated_reset_count);

static struct attribute *spi_hid_attrs[] = {
	&dev_attr_bus_error_count.attr,
	&dev_attr_regulator_error_count.attr,
	&dev_attr_device_initiated_reset_count.attr,
	NULL	/* Terminator */
};

static const struct attribute_group spi_hid_group = {
	.attrs = spi_hid_attrs,
};

const struct attribute_group *spi_hid_groups[] = {
	&spi_hid_group,
	NULL
};
EXPORT_SYMBOL_GPL(spi_hid_groups);

/*
 * At the end of probe we initialize the device:
 *   0) assert reset, bias the interrupt line
 *   1) sleep minimal reset delay
 *   2) power up the device
 *   3) deassert reset (high)
 * After this we expect an IRQ with a reset response.
 */
static int spi_hid_dev_init(struct spi_hid *shid)
{
	struct spi_device *spi = shid->spi;
	struct device *dev = &spi->dev;
	int error;

	shid->ops->assert_reset(shid->ops);

	shid->ops->sleep_minimal_reset_delay(shid->ops);

	error = shid->ops->power_up(shid->ops);
	if (error) {
		dev_err(dev, "%s: could not power up\n", __func__);
		shid->regulator_error_count++;
		shid->regulator_last_error = error;
		return error;
	}

	shid->ops->deassert_reset(shid->ops);

	enable_irq(spi->irq);

	return 0;
}

static void spi_hid_panel_follower_work(struct work_struct *work)
{
	struct spi_hid *shid = container_of(work, struct spi_hid,
					    panel_follower_work);
	int error;

	if (!shid->desc.hid_version)
		error = spi_hid_dev_init(shid);
	else
		error = spi_hid_resume(shid);
	if (error)
		dev_warn(&shid->spi->dev, "Power on failed: %d\n", error);
	else
		WRITE_ONCE(shid->panel_follower_work_finished, true);
}

static int spi_hid_panel_follower_resume(struct drm_panel_follower *follower)
{
	struct spi_hid *shid = container_of(follower, struct spi_hid, panel_follower);

	/*
	 * Powering on a touchscreen can be a slow process. Queue the work to
	 * the system workqueue so we don't block the panel's power up.
	 */
	WRITE_ONCE(shid->panel_follower_work_finished, false);
	schedule_work(&shid->panel_follower_work);

	return 0;
}

static int spi_hid_panel_follower_suspend(struct drm_panel_follower *follower)
{
	struct spi_hid *shid = container_of(follower, struct spi_hid, panel_follower);

	cancel_work_sync(&shid->panel_follower_work);

	if (!READ_ONCE(shid->panel_follower_work_finished))
		return 0;

	return spi_hid_suspend(shid);
}

static const struct drm_panel_follower_funcs
				spi_hid_panel_follower_prepare_funcs = {
	.panel_prepared = spi_hid_panel_follower_resume,
	.panel_unpreparing = spi_hid_panel_follower_suspend,
};

static int spi_hid_register_panel_follower(struct spi_hid *shid)
{
	struct device *dev = &shid->spi->dev;

	shid->panel_follower.funcs = &spi_hid_panel_follower_prepare_funcs;

	/*
	 * If we're not in control of our own power up/power down then we can't
	 * do the logic to manage wakeups. Give a warning if a user thought
	 * that was possible then force the capability off.
	 */
	if (device_can_wakeup(dev)) {
		dev_warn(dev, "Can't wakeup if following panel\n");
		device_set_wakeup_capable(dev, false);
	}

	return drm_panel_add_follower(dev, &shid->panel_follower);
}

int spi_hid_core_probe(struct spi_device *spi, struct spihid_ops *ops,
		       struct spi_hid_conf *conf)
{
	struct device *dev = &spi->dev;
	struct spi_hid *shid;
	int error;

	if (spi->irq <= 0)
		return dev_err_probe(dev, spi->irq ?: -EINVAL, "Missing IRQ\n");

	shid = devm_kzalloc(dev, sizeof(*shid), GFP_KERNEL);
	if (!shid)
		return -ENOMEM;

	shid->spi = spi;
	shid->power_state = HIDSPI_ON;
	shid->ops = ops;
	shid->conf = conf;
	set_bit(SPI_HID_RESET_PENDING, &shid->flags);
	shid->is_panel_follower = drm_is_panel_follower(&spi->dev);

	spi_set_drvdata(spi, shid);

	/* Using now populated conf let's pre-calculate the read approvals */
	spi_hid_populate_read_approvals(shid->conf, shid->read_approval_header,
					shid->read_approval_body);

	mutex_init(&shid->output_lock);
	mutex_init(&shid->power_lock);
	mutex_init(&shid->io_lock);
	init_completion(&shid->output_done);

	INIT_WORK(&shid->reset_work, spi_hid_reset_work);
	INIT_WORK(&shid->panel_follower_work, spi_hid_panel_follower_work);

	/*
	 * We need to allocate the buffer without knowing the maximum
	 * size of the reports. Let's use SZ_2K, then we do the
	 * real computation later.
	 */
	error = spi_hid_alloc_buffers(shid, SZ_2K);
	if (error)
		return error;

	error = devm_request_threaded_irq(dev, spi->irq, NULL, spi_hid_dev_irq,
					  IRQF_ONESHOT | IRQF_NO_AUTOEN, dev_name(&spi->dev), shid);
	if (error) {
		dev_err(dev, "%s: unable to request threaded IRQ\n", __func__);
		return error;
	}
	if (device_may_wakeup(dev)) {
		error = dev_pm_set_wake_irq(dev, spi->irq);
		if (error) {
			dev_err(dev, "%s: failed to set wake IRQ\n", __func__);
			return error;
		}
	}

	if (shid->is_panel_follower) {
		error = spi_hid_register_panel_follower(shid);
		if (error) {
			dev_err_probe(dev, error,
				      "Failed to register panel follower");
			goto err_wake_irq;
		}
	} else {
		error = spi_hid_dev_init(shid);
		if (error)
			goto err_wake_irq;
	}

	dev_dbg(dev, "%s: d3 -> %s\n", __func__,
		spi_hid_power_mode_string(shid->power_state));

	return 0;

err_wake_irq:
	if (device_may_wakeup(dev))
		dev_pm_clear_wake_irq(dev);
	return error;
}
EXPORT_SYMBOL_GPL(spi_hid_core_probe);

void spi_hid_core_remove(struct spi_device *spi)
{
	struct spi_hid *shid = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	int error;

	if (shid->is_panel_follower)
		drm_panel_remove_follower(&shid->panel_follower);
	else
		disable_irq(spi->irq);

	cancel_work_sync(&shid->reset_work);

	spi_hid_stop_hid(shid);

	if (shid->power_state != HIDSPI_OFF) {
		shid->ops->assert_reset(shid->ops);
		error = shid->ops->power_down(shid->ops);
		if (error)
			dev_err(dev, "failed to disable regulator\n");
	}

	if (device_may_wakeup(dev))
		dev_pm_clear_wake_irq(dev);
}
EXPORT_SYMBOL_GPL(spi_hid_core_remove);

static int spi_hid_core_pm_suspend(struct device *dev)
{
	struct spi_hid *shid = dev_get_drvdata(dev);

	if (shid->is_panel_follower)
		return 0;

	return spi_hid_suspend(shid);
}

static int spi_hid_core_pm_resume(struct device *dev)
{
	struct spi_hid *shid = dev_get_drvdata(dev);

	if (shid->is_panel_follower)
		return 0;

	return spi_hid_resume(shid);
}

const struct dev_pm_ops spi_hid_core_pm = {
	SYSTEM_SLEEP_PM_OPS(spi_hid_core_pm_suspend, spi_hid_core_pm_resume)
};
EXPORT_SYMBOL_GPL(spi_hid_core_pm);

MODULE_DESCRIPTION("HID over SPI transport driver");
MODULE_AUTHOR("Dmitry Antipov <dmanti@microsoft.com>");
MODULE_LICENSE("GPL");
