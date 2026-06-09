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

#include <linux/completion.h>
#include <linux/crc32.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/hid.h>
#include <linux/hid-over-spi.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/unaligned.h>

#define SPI_HID_OUTPUT_REPORT_CONTENT_ID_DESC_REQUEST	0x00

#define SPI_HID_RESP_TIMEOUT	1000

/* Protocol message size constants */
#define SPI_HID_OUTPUT_HEADER_LEN		8

/* flags */
/*
 * ready flag indicates that the FW is ready to accept commands and
 * requests. The FW becomes ready after sending the report descriptor.
 */
#define SPI_HID_READY	0

/* Raw input buffer with data from the bus */
struct spi_hid_input_buf {
	u8 header[HIDSPI_INPUT_HEADER_SIZE];
	u8 body[HIDSPI_INPUT_BODY_HEADER_SIZE];
	u8 content[];
};

/* Raw output report buffer to be put on the bus */
struct spi_hid_output_buf {
	u8 header[SPI_HID_OUTPUT_HEADER_LEN];
	u8 content[];
};

/* Data necessary to send an output report */
struct spi_hid_output_report {
	u8 report_type;
	u16 content_length;
	u8 content_id;
	u8 *content;
};

/* Processed data from a device descriptor */
struct spi_hid_device_descriptor {
	u16 hid_version;
	u16 report_descriptor_length;
	u16 max_input_length;
	u16 max_output_length;
	u16 max_fragment_length;
	u16 vendor_id;
	u16 product_id;
	u16 version_id;
	u8 no_output_report_ack;
};

/* struct spi_hid_conf - Conf provided to the core */
struct spi_hid_conf {
	u32 input_report_header_address;
	u32 input_report_body_address;
	u32 output_report_address;
	u8 read_opcode;
	u8 write_opcode;
};

/**
 * struct spihid_ops - Ops provided to the core
 * @power_up: do sequencing to power up the device
 * @power_down: do sequencing to power down the device
 * @assert_reset: do sequencing to assert the reset line
 * @deassert_reset: do sequencing to deassert the reset line
 * @sleep_minimal_reset_delay: minimal sleep delay during reset
 */
struct spihid_ops {
	int (*power_up)(struct spihid_ops *ops);
	int (*power_down)(struct spihid_ops *ops);
	int (*assert_reset)(struct spihid_ops *ops);
	int (*deassert_reset)(struct spihid_ops *ops);
	void (*sleep_minimal_reset_delay)(struct spihid_ops *ops);
};

/* Driver context */
struct spi_hid {
	struct spi_device	*spi;	/* spi device. */
	struct hid_device	*hid;	/* pointer to corresponding HID dev. */

	struct spihid_ops	*ops;
	struct spi_hid_conf	*conf;

	struct spi_hid_device_descriptor desc;	/* HID device descriptor. */
	struct spi_hid_output_buf *output;	/* Output buffer. */
	struct spi_hid_input_buf *input;	/* Input buffer. */
	struct spi_hid_input_buf *response;	/* Response buffer. */

	u16 response_length;
	u16 bufsize;

	enum hidspi_power_state power_state;

	u8 reset_attempts;	/* The number of reset attempts. */

	unsigned long flags;	/* device flags. */

	/* Control lock to make sure one output transaction at a time. */
	struct mutex output_lock;
	struct completion output_done;

	u32 report_descriptor_crc32;	/* HID report descriptor crc32 checksum. */

	u32 regulator_error_count;
	int regulator_last_error;
	u32 bus_error_count;
	int bus_last_error;
	u32 dir_count;	/* device initiated reset count. */
};

static struct hid_ll_driver spi_hid_ll_driver;

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

static void spi_hid_stop_hid(struct spi_hid *shid)
{
	struct hid_device *hid = shid->hid;

	shid->hid = NULL;
	clear_bit(SPI_HID_READY, &shid->flags);

	if (hid)
		hid_destroy_device(hid);
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

	shid->hid = hid;

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

/* This is a placeholder. Will be implemented in the next patch. */
static irqreturn_t spi_hid_dev_irq(int irq, void *_shid)
{
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

	if (shid->desc.no_output_report_ack)
		error = spi_hid_send_output_report(shid, &report);
	else
		error = spi_hid_sync_request(shid, &report);

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

	spi_set_drvdata(spi, shid);

	mutex_init(&shid->output_lock);
	init_completion(&shid->output_done);

	/*
	 * we need to allocate the buffer without knowing the maximum
	 * size of the reports. Let's use SZ_2K, then we do the
	 * real computation later.
	 */
	error = spi_hid_alloc_buffers(shid, SZ_2K);
	if (error)
		return error;

	/*
	 * At the end of probe we initialize the device:
	 *   0) assert reset, bias the interrupt line
	 *   1) sleep minimal reset delay
	 *   2) request IRQ
	 *   3) power up the device
	 *   4) deassert reset (high)
	 * After this we expect an IRQ with a reset response.
	 */

	shid->ops->assert_reset(shid->ops);

	shid->ops->sleep_minimal_reset_delay(shid->ops);

	error = devm_request_threaded_irq(dev, spi->irq, NULL, spi_hid_dev_irq,
					  IRQF_ONESHOT, dev_name(&spi->dev), shid);
	if (error) {
		dev_err(dev, "%s: unable to request threaded IRQ\n", __func__);
		return error;
	}

	error = shid->ops->power_up(shid->ops);
	if (error) {
		dev_err(dev, "%s: could not power up\n", __func__);
		return error;
	}

	shid->ops->deassert_reset(shid->ops);

	dev_dbg(dev, "%s: d3 -> %s\n", __func__,
		spi_hid_power_mode_string(shid->power_state));

	error = spi_hid_create_device(shid);
	if (error)
		return error;

	return 0;
}
EXPORT_SYMBOL_GPL(spi_hid_core_probe);

void spi_hid_core_remove(struct spi_device *spi)
{
	struct spi_hid *shid = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	int error;

	spi_hid_stop_hid(shid);

	shid->ops->assert_reset(shid->ops);
	error = shid->ops->power_down(shid->ops);
	if (error)
		dev_err(dev, "failed to disable regulator\n");
}
EXPORT_SYMBOL_GPL(spi_hid_core_remove);

MODULE_DESCRIPTION("HID over SPI transport driver");
MODULE_AUTHOR("Dmitry Antipov <dmanti@microsoft.com>");
MODULE_LICENSE("GPL");
