// SPDX-License-Identifier: GPL-2.0
/*
 * HID over SPI protocol, ACPI related code
 *
 * Copyright (c) 2021 Microsoft Corporation
 * Copyright (c) 2026 Google LLC
 *
 * This code was forked out of the HID over SPI core code, which is partially
 * based on "HID over I2C protocol implementation:
 *
 * Copyright (c) 2012 Benjamin Tissoires <benjamin.tissoires@gmail.com>
 * Copyright (c) 2012 Ecole Nationale de l'Aviation Civile, France
 * Copyright (c) 2012 Red Hat, Inc
 *
 * which in turn is partially based on "USB HID support for Linux":
 *
 * Copyright (c) 1999 Andreas Gal
 * Copyright (c) 2000-2005 Vojtech Pavlik <vojtech@suse.cz>
 * Copyright (c) 2005 Michael Haboustak <mike-@cinci.rr.com> for Concept2, Inc
 * Copyright (c) 2007-2008 Oliver Neukum
 * Copyright (c) 2006-2010 Jiri Kosina
 */

#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/reset.h>
#include <linux/uuid.h>

#include "spi-hid.h"

/* Config structure is filled with data from ACPI */
struct spi_hid_acpi_config {
	struct spihid_ops ops;

	struct spi_hid_conf property_conf;
	u32 post_power_on_delay_ms;
	u32 minimal_reset_delay_ms;
	struct acpi_device *adev;
};

/* HID SPI Device: 6e2ac436-0fcf41af-a265-b32a220dcfab */
static guid_t spi_hid_guid =
	GUID_INIT(0x6E2AC436, 0x0FCF, 0x41AF,
		  0xA2, 0x65, 0xB3, 0x2A, 0x22, 0x0D, 0xCF, 0xAB);

static int spi_hid_acpi_populate_config(struct spi_hid_acpi_config *conf,
					struct acpi_device *adev)
{
	acpi_handle handle = acpi_device_handle(adev);
	union acpi_object *obj;

	conf->adev = adev;

	/* Revision 3 for HID over SPI V1, see specification. */
	obj = acpi_evaluate_dsm_typed(handle, &spi_hid_guid, 3, 1, NULL,
				      ACPI_TYPE_INTEGER);
	if (!obj) {
		acpi_handle_err(handle,
				"Error _DSM call to get HID input report header address failed");
		return -ENODEV;
	}
	conf->property_conf.input_report_header_address = obj->integer.value;
	ACPI_FREE(obj);

	obj = acpi_evaluate_dsm_typed(handle, &spi_hid_guid, 3, 2, NULL,
				      ACPI_TYPE_INTEGER);
	if (!obj) {
		acpi_handle_err(handle,
				"Error _DSM call to get HID input report body address failed");
		return -ENODEV;
	}
	conf->property_conf.input_report_body_address = obj->integer.value;
	ACPI_FREE(obj);

	obj = acpi_evaluate_dsm_typed(handle, &spi_hid_guid, 3, 3, NULL,
				      ACPI_TYPE_INTEGER);
	if (!obj) {
		acpi_handle_err(handle,
				"Error _DSM call to get HID output report header address failed");
		return -ENODEV;
	}
	conf->property_conf.output_report_address = obj->integer.value;
	ACPI_FREE(obj);

	obj = acpi_evaluate_dsm_typed(handle, &spi_hid_guid, 3, 4, NULL,
				      ACPI_TYPE_BUFFER);
	if (!obj) {
		acpi_handle_err(handle,
				"Error _DSM call to get HID read opcode failed");
		return -ENODEV;
	}
	if (obj->buffer.length == 1) {
		conf->property_conf.read_opcode = obj->buffer.pointer[0];
	} else {
		acpi_handle_err(handle,
				"Error _DSM call to get HID read opcode, too long buffer");
		ACPI_FREE(obj);
		return -ENODEV;
	}
	ACPI_FREE(obj);

	obj = acpi_evaluate_dsm_typed(handle, &spi_hid_guid, 3, 5, NULL,
				      ACPI_TYPE_BUFFER);
	if (!obj) {
		acpi_handle_err(handle,
				"Error _DSM call to get HID write opcode failed");
		return -ENODEV;
	}
	if (obj->buffer.length == 1) {
		conf->property_conf.write_opcode = obj->buffer.pointer[0];
	} else {
		acpi_handle_err(handle,
				"Error _DSM call to get HID write opcode, too long buffer");
		ACPI_FREE(obj);
		return -ENODEV;
	}
	ACPI_FREE(obj);

	/* Value not provided in ACPI,*/
	conf->post_power_on_delay_ms = 5;
	conf->minimal_reset_delay_ms = 150;

	if (!acpi_has_method(handle, "_RST")) {
		acpi_handle_err(handle, "No reset method for acpi handle");
		return -EINVAL;
	}

	/* FIXME: not reading hid-over-spi-flags, multi-SPI not supported */

	return 0;
}

static int spi_hid_acpi_power_none(struct spihid_ops *ops)
{
	return 0;
}

static int spi_hid_acpi_power_down(struct spihid_ops *ops)
{
	struct spi_hid_acpi_config *conf = container_of(ops,
							struct spi_hid_acpi_config,
							ops);

	return acpi_device_set_power(conf->adev, ACPI_STATE_D3);
}

static int spi_hid_acpi_power_up(struct spihid_ops *ops)
{
	struct spi_hid_acpi_config *conf = container_of(ops,
							struct spi_hid_acpi_config,
							ops);
	int error;

	error = acpi_device_set_power(conf->adev, ACPI_STATE_D0);
	if (error) {
		dev_err(&conf->adev->dev, "Error could not power up ACPI device: %d.", error);
		return error;
	}

	if (conf->post_power_on_delay_ms)
		msleep(conf->post_power_on_delay_ms);

	return 0;
}

static int spi_hid_acpi_assert_reset(struct spihid_ops *ops)
{
	return 0;
}

static int spi_hid_acpi_deassert_reset(struct spihid_ops *ops)
{
	struct spi_hid_acpi_config *conf = container_of(ops,
							struct spi_hid_acpi_config,
							ops);

	return device_reset(&conf->adev->dev);
}

static void spi_hid_acpi_sleep_minimal_reset_delay(struct spihid_ops *ops)
{
	struct spi_hid_acpi_config *conf = container_of(ops,
							struct spi_hid_acpi_config,
							ops);
	fsleep(1000 * conf->minimal_reset_delay_ms);
}

static int spi_hid_acpi_probe(struct spi_device *spi)
{
	struct device *dev = &spi->dev;
	struct acpi_device *adev;
	struct spi_hid_acpi_config *config;
	int error;

	adev = ACPI_COMPANION(dev);
	if (!adev) {
		dev_err(dev, "Error could not get ACPI device.");
		return -ENODEV;
	}

	config = devm_kzalloc(dev, sizeof(struct spi_hid_acpi_config),
			      GFP_KERNEL);
	if (!config)
		return -ENOMEM;

	if (acpi_device_power_manageable(adev)) {
		config->ops.power_up = spi_hid_acpi_power_up;
		config->ops.power_down = spi_hid_acpi_power_down;
	} else {
		config->ops.power_up = spi_hid_acpi_power_none;
		config->ops.power_down = spi_hid_acpi_power_none;
	}
	config->ops.assert_reset = spi_hid_acpi_assert_reset;
	config->ops.deassert_reset = spi_hid_acpi_deassert_reset;
	config->ops.sleep_minimal_reset_delay =
		spi_hid_acpi_sleep_minimal_reset_delay;

	error = spi_hid_acpi_populate_config(config, adev);
	if (error) {
		dev_err(dev, "%s: unable to populate config data.", __func__);
		return error;
	}

	return spi_hid_core_probe(spi, &config->ops, &config->property_conf);
}

static const struct acpi_device_id spi_hid_acpi_match[] = {
	{ "ACPI0C51", 0 },
	{ "PNP0C51", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, spi_hid_acpi_match);

static struct spi_driver spi_hid_acpi_driver = {
	.driver = {
		.name	= "spi_hid_acpi",
		.owner	= THIS_MODULE,
		.pm	= &spi_hid_core_pm,
		.acpi_match_table = spi_hid_acpi_match,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
		.dev_groups = spi_hid_groups,
	},
	.probe		= spi_hid_acpi_probe,
	.remove		= spi_hid_core_remove,
};

module_spi_driver(spi_hid_acpi_driver);

MODULE_DESCRIPTION("HID over SPI ACPI transport driver");
MODULE_AUTHOR("Angela Czubak <aczubak@google.com>");
MODULE_LICENSE("GPL");
