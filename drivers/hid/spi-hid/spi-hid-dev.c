/*
 * spi-hid-dev.h
 *
 * Copyright (c) 2020 Microsoft Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

/*
 *This file implements a connection to a peer spi-hid device. This includes
 * the handshake procedure, irq handling (including irq behaviour for device
 * sleep modes), buffer allocation and input/output report transactions.
 * It relies on the protocol definitions (-protocol.h, -device-descriptor.h),
 * the bus transaction implementation (-bus.h) for message transfers and
 * a fast input buffer pool (-pool.h) to quickly allocate input buffers in
 * irq context.
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>

#include "spi-hid-dev.h"
#include "spi-hid-bus.h"
#include "spi-hid-pool.h"
#include "spi-hid-protocol.h"

/* - Concurrency and ownership -
 * This file implements a connection to a peer spi-hid device allowing for
 * low latency input report transactions and ouput report transactions.
 * Since an instance of the spi-hid-dev may be accessed by different contexts
 * concurrently (irq context, spi irq context, worker threads and client calls)
 * all struct members must be protected from data races.
 *
 * The instance is mainly protected by access rules depending on it's ready
 * state, tracked by the _READY flag. The flag may only be toggled using the
 * atomic set/clear_bit functions.
 *
 * In the unready state (_READY == 0) the instance is completely owned by the
 * client (i.e external creator/user of the instance) and the client is
 * responsible for limiting the access to the instance. In this state, the
 * client may only call the _init, _reset and _destroy functions, transferring
 * ownership to the instance itself, returning the ownership to the instance
 * (after gaining it in the _reset callback) and destroying it respectively.
 *
 * Upon activating the irq handler, the init function transfers the ownership
 * to the irq context and in turn the spi_hid_bus instance. Since the bus is
 * the owner of the instance, only the bus callbacks may mutate the state.
 * The bus callbacks may retain the ownership by returning the appropriate
 * value to the bus.
 *
 * When the ready state has been reached (_READY == 1), the ownership of the
 * instance members is divided:
 *
 * bus should be thread safe to access. The client may access it through the
 * functions exposed through this file.
 *
 * hid_desc_addr, buffer_alloc_work, wait and the event_callback(_context)
 * should be set in init() and be considered immutable / thread-safe until
 * destroy() is called
 *
 * desc is read during the handshake and should be considered immutable during
 * the ready state and completely invalid otherwise.
 *
 * input/output.init_buf is used in the handshake, owned by bus, should not be
 * accessed otherwise
 *
 * input.pool is valid only in the ready state. Is thread safe under its own
 * rules.
 *
 * output.* is valid only in the ready state. Protected by the output.lock
 * mutex otherwise. Setting the _OUTPUT_PENDING flag transfers ownership from
 * mutex to bus and vice versa.
 *
 * The ASLEEP state flag is completely owned by the client. The client is
 * responsible for setting the device in a quiesced sleep mode before setting
 * the flag and clearing it before waking the device.
 *
 * See the state bit macros in spi-hid-dev.h
 */

static irqreturn_t spi_hid_dev_irq(int irq, void *dev_id)
{
	struct spi_hid_dev *dev = (struct spi_hid_dev *)(dev_id);

	disable_irq_nosync(dev->spi->irq);
	if (test_bit(SPI_HID_DEV_ASLEEP, &dev->flags) && dev->event_callback) {
		set_bit(SPI_HID_DEV_WAKEUP, &dev->flags);
		dev->event_callback(dev->event_callback_context, SPI_HID_DEV_EVENT_WAKEUP);
		return IRQ_HANDLED;
	}

	set_bit(SPI_HID_DEV_TRANSACTION_ONGOING, &dev->flags);

	if (test_bit(SPI_HID_DEV_READY, &dev->flags)) {
		spi_hid_bus_input(&dev->bus, dev->desc.input_register,
				spi_hid_pool_take_input(&dev->input.buf), dev->desc.max_input_length);
	} else {
		spi_hid_bus_input(&dev->bus, SPI_HID_DEFAULT_INPUT_REGISTER,
				dev->input.init_buf, sizeof(spi_hid_input_init_buf));
	}

	return IRQ_HANDLED;
}

static void spi_hid_dev_event(struct spi_hid_dev *dev, int event) {
	if (event == SPI_HID_DEV_EVENT_ERROR || event == SPI_HID_DEV_EVENT_RESET) {
		dev_err(&dev->spi->dev, "Error or reset\n");
		clear_bit(SPI_HID_DEV_READY, &dev->flags);
	}

	if (dev->event_callback)
		dev->event_callback(dev->event_callback_context, event);
}

static void spi_hid_dev_input_callback(void *context,
		struct spi_hid_input_buf *buf)
{
	struct spi_hid_dev *dev = (struct spi_hid_dev *)context;
	struct spi_hid_input_header header;
        struct spi_hid_input_body body;
	int reenable_irq = 0;

	spi_hid_input_header(buf->header.header, &header);
	spi_hid_input_body(buf->body.body, &body);

        if (body.content_id == 0 || body.content_id == 0xFF) {
                dev_warn(&dev->spi->dev, "Received bad ID: %u, header.report_length: %u, content_length: %u, buf_len: %u\n",
                        body.content_id, header.report_length, body.content_length, test_bit(SPI_HID_DEV_READY, &dev->flags) ?
                        (dev->desc.max_input_length - sizeof(struct spi_hid_input_buf) - SPI_HID_INPUT_BODY_LEN) :
                        sizeof(struct spi_hid_device_desc_raw));
        }
        if (body.content_length > header.report_length ||
                body.content_length > (test_bit(SPI_HID_DEV_READY, &dev->flags) ?
                    (dev->desc.max_input_length - sizeof(struct spi_hid_input_buf) - SPI_HID_INPUT_BODY_LEN) :
                    sizeof(struct spi_hid_device_desc_raw))) {
                if (test_bit(SPI_HID_DEV_READY, &dev->flags)) {
                        spi_hid_pool_drop_input(&dev->input.buf, buf);
                        reenable_irq = 1;
                }
                dev_err(&dev->spi->dev, "Received bad content_length: %u, header.report_length: %u, ID: %u, buf_len: %u\n",
                        body.content_length, header.report_length, body.content_id, test_bit(SPI_HID_DEV_READY, &dev->flags) ?
                        (dev->desc.max_input_length - sizeof(struct spi_hid_input_buf) - SPI_HID_INPUT_BODY_LEN) :
                        sizeof(struct spi_hid_device_desc_raw));
        } else {
                switch (header.report_type) {
                case SPI_HID_REPORT_TYPE_DATA:
                        spi_hid_pool_push_report(&dev->input.buf, buf);
                        //trace_spi_hid_bus_pending(&dev->spi->dev, pending);
                        spi_hid_dev_event(dev, SPI_HID_DEV_EVENT_INPUT_REPORT);
                        reenable_irq = 1;
                        break;
                case SPI_HID_REPORT_TYPE_RESET_RESP:
                        dev_err(&dev->spi->dev, "Received reset\n");
                        spi_hid_dev_event(dev, SPI_HID_DEV_EVENT_RESET);
                        break;
                case SPI_HID_REPORT_TYPE_DEVICE_DESC:
                        if (!test_bit(SPI_HID_DEV_READY, &dev->flags)) {
                                spi_hid_device_descriptor_parse(
                                        (struct spi_hid_device_desc_raw *)buf->content, &dev->desc);
                                schedule_work(&dev->buffer_alloc_work);
                                break;
                        }
                        /* fall through */
                case SPI_HID_REPORT_TYPE_COMMAND_RESP:
                case SPI_HID_REPORT_TYPE_GET_FEATURE_RESP:
                case SPI_HID_REPORT_TYPE_REPORT_DESC:
                        if (test_bit(SPI_HID_DEV_READY, &dev->flags)) {
                                spi_hid_pool_push_response(&dev->input.buf, buf);
                                spi_hid_dev_event(dev, SPI_HID_DEV_EVENT_RESPONSE);
                                reenable_irq = 1;
                                break;
                        } else {
                                dev_err(&dev->spi->dev,
                                        "Received unexpected response from device: 0x%x\n",
                                        header.report_type);
                                spi_hid_dev_event(dev, SPI_HID_DEV_EVENT_ERROR);
                                break;
                        }
                default:
                        dev_err(&dev->spi->dev, "Received unknown input report type 0x%x\n",
                                header.report_type);
                        spi_hid_dev_event(dev, SPI_HID_DEV_EVENT_ERROR);
                        break;
            }
        }

	clear_bit(SPI_HID_DEV_TRANSACTION_ONGOING, &dev->flags);
	wake_up(&dev->wait);
	if (reenable_irq) enable_irq(dev->spi->irq);
}

// instance ownership passed from scheduling context
static void spi_hid_dev_buffer_alloc_work(struct work_struct *work)
{
	struct spi_hid_dev *dev = container_of(work, struct spi_hid_dev, buffer_alloc_work);

	//trace_spi_hid_dev_alloc_begin(dev);

	if (dev->desc.hid_version != SPI_HID_SUPPORTED_VERSION) {
		dev_err(&dev->spi->dev,
				"Unsupported device descriptor version %4x\n",
				dev->desc.hid_version);
		spi_hid_dev_event(dev, SPI_HID_DEV_EVENT_ERROR);
		return; // <- ownership passed to client via error event
	}

	if (
		spi_hid_pool_init(
			&dev->input.buf, 16,
			dev->desc.max_input_length,
			GFP_KERNEL
		) ||
		!(dev->output.buf = kzalloc(
			sizeof(struct spi_hid_output_buf) + dev->desc.max_output_length,
			GFP_KERNEL)
		)
	) { // ownership passed to client via error event
		/* No need to free dev->output.buf.  Either spi_hid_pool_init failed so no kzalloc happened
			or spi_hid_pool_init free worked and freed and kzalloc failed */
		dev_err(&dev->spi->dev, "spi_hid_pool_init out of mem\n");
		if (dev->input.buf.buf != NULL) {
			spi_hid_pool_destroy(&dev->input.buf);
		}
		spi_hid_dev_event(dev, SPI_HID_DEV_EVENT_ERROR);
	} else {
		set_bit(SPI_HID_DEV_READY, &dev->flags);
		spi_hid_dev_event(dev, SPI_HID_DEV_EVENT_READY);
		enable_irq(dev->spi->irq);
	}
	//trace_spi_hid_bus_alloc_end(dev);
}

static int spi_hid_dev_output_async(struct spi_hid_dev *dev,
		struct spi_hid_output_buf *buf, u16 length)
{
	set_bit(SPI_HID_DEV_TRANSACTION_ONGOING, &dev->flags);

	spi_hid_bus_output(&dev->bus, buf, length);

	if (!wait_event_timeout(
		dev->wait,
		!test_bit(SPI_HID_DEV_TRANSACTION_ONGOING, &dev->flags),
		msecs_to_jiffies(2000)
	)) {
		dev_err(&dev->spi->dev, "Output report timed out!\n");
		return -ETIMEDOUT;
	};

	return dev->output.status;
}

// output ownership is assumed granted by output.lock holder via _OUTPUT_PENDING
static void spi_hid_dev_output_callback(void *context, int status, int error)
{
	struct spi_hid_dev *dev = (struct spi_hid_dev *)context;

	dev->output.status = status;
	dev->output.err = error;

	// output ownership returned to output.lock holder
	clear_bit(SPI_HID_DEV_TRANSACTION_ONGOING, &dev->flags);
	wake_up(&dev->wait);
	enable_irq(dev->spi->irq);
}

static void spi_hid_dev_error_callback(void *context, int error, int cause)
{
	struct spi_hid_dev *dev = (struct spi_hid_dev *)context;

	if (test_bit(SPI_HID_DEV_IN_D3, &dev->flags)) {
		dev_err(&dev->spi->dev, "%s called while in D3, ignoring the error\n", __func__);
		return;
	}

	spi_hid_dev_event(dev, SPI_HID_DEV_EVENT_ERROR);
	clear_bit(SPI_HID_DEV_TRANSACTION_ONGOING, &dev->flags);
	wake_up(&dev->wait);
	(void)error;
	(void)cause;
}

// Client interface functions

int spi_hid_dev_get_input_report(struct spi_hid_dev *dev, struct spi_hid_input_report *report)
{
        struct spi_hid_input_buf *buf;

	if (!test_bit(SPI_HID_DEV_READY, &dev->flags)) {
		dev_err(&dev->spi->dev, "%s called in unready state\n", __func__);
		return -ENOTCONN;
	}

        spi_hid_pool_pop_report(&dev->input.buf, (void **)&buf);

        if (buf==0) return -1;

        spi_hid_input_report_prepare(buf, report);

        return 0;
}

int spi_hid_dev_get_response(struct spi_hid_dev *dev,
		struct spi_hid_input_report *report)
{
	struct spi_hid_input_buf *buf;
	if (!test_bit(SPI_HID_DEV_READY, &dev->flags)) {
		dev_err(&dev->spi->dev, "%s called in unready state\n", __func__);
		return -ENOTCONN;
	}
	buf = (struct spi_hid_input_buf *)
			spi_hid_pool_pop_response(&dev->input.buf);

	spi_hid_input_report_prepare(buf, report);

	return 0;
}

int spi_hid_dev_output_report(struct spi_hid_dev *dev, u32 output_register,
		struct spi_hid_output_report *report)
{
	int err;
	mutex_lock(&dev->output.lock);
	if (!test_bit(SPI_HID_DEV_READY, &dev->flags)) {
		dev_err(&dev->spi->dev, "%s called in unready state\n", __func__);
		err = -ENOTCONN;
	} else {
		struct spi_hid_output_buf *buf = dev->output.buf;

		// size of the complete body + content
		u16 body_length = sizeof(buf->body) + report->content_length;
		// size of the padded body, the length transmitted for the body
		u16 padded_length = round_up(body_length, 4);
		u8 padding = padded_length - body_length;

		// Spec is unclear if wMaxOutputLength is including body and padding.
		// We'll assume it is. buf->size is the size of the content buffer (no body)
		if (padded_length > dev->desc.max_output_length + sizeof(buf->body)) {
			dev_err(&dev->bus.spi->dev,
					"Output report bigger than max size ((%d +) %d (+ %d) > %d)\n",
					sizeof(buf->body), padded_length, padding,
					dev->desc.max_output_length + sizeof(buf->body));
			err = -E2BIG;
			goto out;
		}

		spi_hid_output_header(buf->header, output_register, padded_length);

		spi_hid_output_body(buf->body, report);

		// We prefer copying the data once rather than scatter sending to minimize
		// time occupying the spi bus. Todo: possibly do DMA as well.
		if (report->content_length)
			memcpy(&buf->content, report->content, report->content_length);
		// Add padding
		memset(&buf->content[report->content_length], 0, padding);

		disable_irq(dev->spi->irq);
		wait_event(dev->wait, !test_bit(SPI_HID_DEV_TRANSACTION_ONGOING,
				&dev->flags));

		// The device may have reset or errored during an ongoing input report
		if (!test_bit(SPI_HID_DEV_READY, &dev->flags)) {
			dev_err(&dev->spi->dev, "%s called in unready state: error or reset during ongoing transaction\n", __func__);
			enable_irq(dev->spi->irq);
			err = -ENOTCONN;
		} else {
			err = spi_hid_dev_output_async(dev, buf,
					sizeof(buf->header) + padded_length);
		}
	}
out:
	mutex_unlock(&dev->output.lock);
	return err;
}

void spi_hid_dev_stop(struct spi_hid_dev *dev)
{
	if (test_bit(SPI_HID_DEV_IRQ_REQUESTED, &dev->flags)) {
		disable_irq(dev->spi->irq); // stop new input report transactions
		free_irq(dev->spi->irq, dev);
		clear_bit(SPI_HID_DEV_IRQ_REQUESTED, &dev->flags);
	} else {
		dev_warn(&dev->spi->dev, "dev_stop called with IRQ flag already cleared\n");
	}
	mutex_lock(&dev->output.lock); // let output report transactions finish
	mutex_unlock(&dev->output.lock);
}

void spi_hid_dev_start(struct spi_hid_dev *dev)
{
	int ret = 0;
	unsigned long irqflags = irq_get_trigger_type(dev->spi->irq) ?: IRQF_TRIGGER_HIGH;

	if (!test_bit(SPI_HID_DEV_IRQ_REQUESTED, &dev->flags)) {
		ret = request_irq(dev->spi->irq, spi_hid_dev_irq, irqflags,
				dev_name(&dev->spi->dev), dev);

		if (ret < 0) {
			dev_warn(&dev->spi->dev,
				"Could not register for %s interrupt, irq = %d, ret = %d\n",
				dev_name(&dev->spi->dev), dev->spi->irq, ret);
		} else {
			set_bit(SPI_HID_DEV_IRQ_REQUESTED, &dev->flags);
		}
	} else {
		dev_warn(&dev->spi->dev, "dev_start called with IRQ flag already set\n");
	}
}

// This is the only place we know that the buffers are no longer used.
// Assumption: irq is already disabled (not reenabled after reset report)
int spi_hid_dev_restart(struct spi_hid_dev *dev)
{
	if (test_bit(SPI_HID_DEV_READY, &dev->flags)) {
		dev_err(&dev->spi->dev, "%s called in ready state\n", __func__);
		return -EISCONN;
	}

	if (spi_hid_pool_reset(&dev->input.buf)) {
                spi_hid_pool_destroy(&dev->input.buf);
        }
	kfree(dev->output.buf);
	dev->output.buf = 0;
	{
		// device_descriptor_request report body is all 0
		u8 mem[sizeof(struct spi_hid_output_buf)] = { 0 };
		struct spi_hid_output_buf *buf = (struct spi_hid_output_buf *)mem;

		spi_hid_output_header(buf->header,
				dev->hid_desc_addr, round_up(sizeof(buf->body), 4));

		spi_hid_dev_output_async(dev, buf, sizeof(buf));
	}
	return 0;
}

void spi_hid_dev_asleep(struct spi_hid_dev *dev)
{
	set_bit(SPI_HID_DEV_ASLEEP, &dev->flags);
}

void spi_hid_dev_awake(struct spi_hid_dev *dev)
{
	clear_bit(SPI_HID_DEV_ASLEEP, &dev->flags);
}

int spi_hid_dev_is_asleep(struct spi_hid_dev *dev)
{
	return test_bit(SPI_HID_DEV_ASLEEP, &dev->flags);
}

int spi_hid_dev_clear_wakeup(struct spi_hid_dev *dev)
{
	if (test_and_clear_bit(SPI_HID_DEV_WAKEUP, &dev->flags)) {
		enable_irq(dev->spi->irq);
		return 1;
	}
	return 0;
}

int spi_hid_dev_get_discarded(struct spi_hid_dev *dev)
{
	if (!test_bit(SPI_HID_DEV_READY, &dev->flags)) {
		dev_err(&dev->spi->dev, "%s called in unready state\n", __func__);
		return -ENOTCONN;
	}
	return spi_hid_pool_get_discarded(&dev->input.buf);
}

int spi_hid_dev_init(struct spi_hid_dev *dev, struct spi_device *spi,
		u16 hid_desc_addr)
{
	dev->spi = spi;
	dev->hid_desc_addr = hid_desc_addr;
	dev->flags = 0;
	spi_hid_bus_init(&dev->bus, spi);
	dev->bus.client = (struct spi_hid_bus_client) {
		.context = dev,
		.input_callback = spi_hid_dev_input_callback,
		.output_callback = spi_hid_dev_output_callback,
		.error_callback = spi_hid_dev_error_callback,
	};
	mutex_init(&dev->output.lock);
	init_waitqueue_head(&dev->wait);
        memset(&dev->input.buf, 0, sizeof(struct spi_hid_pool));
	dev->input.init_buf = kzalloc(sizeof(spi_hid_input_init_buf), GFP_KERNEL);
	if (!dev->input.init_buf) {
		dev_err(&dev->spi->dev, "Failed to alloc init_buf, no memory\n", __func__);
		return -ENOMEM;
	}
	INIT_WORK(&dev->buffer_alloc_work, spi_hid_dev_buffer_alloc_work);

	return 0;
}

void spi_hid_dev_destroy(struct spi_hid_dev *dev)
{
	spi_hid_pool_destroy(&dev->input.buf);
	kfree(dev->output.buf);
	kfree(dev->input.init_buf);
	dev->output.buf = 0;
	dev->input.init_buf = 0;
}
