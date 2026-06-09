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

#include <linux/device.h>
#include <linux/hid.h>
#include <linux/hid-over-spi.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>

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

	enum hidspi_power_state power_state;

	u32 regulator_error_count;
	int regulator_last_error;
	u32 bus_error_count;
	int bus_last_error;
	u32 dir_count;	/* device initiated reset count. */
};

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

static irqreturn_t spi_hid_dev_irq(int irq, void *_shid)
{
	return IRQ_HANDLED;
}

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

	return 0;
}
EXPORT_SYMBOL_GPL(spi_hid_core_probe);

void spi_hid_core_remove(struct spi_device *spi)
{
	struct spi_hid *shid = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	int error;

	shid->ops->assert_reset(shid->ops);
	error = shid->ops->power_down(shid->ops);
	if (error)
		dev_err(dev, "failed to disable regulator\n");
}
EXPORT_SYMBOL_GPL(spi_hid_core_remove);

MODULE_DESCRIPTION("HID over SPI transport driver");
MODULE_AUTHOR("Dmitry Antipov <dmanti@microsoft.com>");
MODULE_LICENSE("GPL");
