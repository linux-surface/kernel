/*
 * spi-hid-device-descriptor.h
 *
 * Copyright (c) 2020 Microsoft Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#ifndef SPI_HID_DEVICE_DESCRIPTOR_H
#define SPI_HID_DEVICE_DESCRIPTOR_H

#include <linux/device.h>

// Note: spec claims "big-endian byte order [..] most-significant byte is stored
// first in the field.", it appears the d5 is using little-endian byte order..
struct spi_hid_device_desc_raw {
	__le16 wDeviceDescLength;
	__le16 bcdVersion;
	__le16 wReportDescLength;
	__le16 wReportDescRegister;
	__le16 wInputRegister;
	__le16 wMaxInputLength;
	__le16 wOutputRegister;
	__le16 wMaxOutputLength;
	__le16 wCommandRegister;
	__le16 wVendorID;
	__le16 wProductID;
	__le16 wVersionID;
	u8  bPowerCapabilities;
	u8  reserved[3];
} __packed;

struct spi_hid_device_descriptor {
	u16 hid_version;
	u16 device_descriptor_register;
	u16 report_descriptor_length;
	u16 report_descriptor_register;
	u16 input_register;
	u16 max_input_length;
	u16 output_register;
	u16 max_output_length;
	u16 command_register;
	u16 vendor_id;
	u16 product_id;
	u16 version_id;
	u8 device_power_support;
	u8 power_response_delay;
};

static inline void spi_hid_device_descriptor_parse(
		struct spi_hid_device_desc_raw *raw,
		struct spi_hid_device_descriptor *desc)
{
	desc->hid_version                = le16_to_cpu(raw->bcdVersion);
	desc->report_descriptor_length   = le16_to_cpu(raw->wReportDescLength);
	desc->report_descriptor_register = le16_to_cpu(raw->wReportDescRegister);
	desc->input_register             = le16_to_cpu(raw->wInputRegister);
	desc->max_input_length           = le16_to_cpu(raw->wMaxInputLength);
	desc->output_register            = le16_to_cpu(raw->wOutputRegister);
	desc->max_output_length          = le16_to_cpu(raw->wMaxOutputLength);
	desc->command_register           = le16_to_cpu(raw->wCommandRegister);
	desc->vendor_id                  = le16_to_cpu(raw->wVendorID);
	desc->product_id                 = le16_to_cpu(raw->wProductID);
	desc->version_id                 = le16_to_cpu(raw->wVersionID);
	desc->device_power_support = ((raw->bPowerCapabilities >> 6) & 0x03);
	desc->power_response_delay = ((raw->bPowerCapabilities) & 0x3F) << 1;
}

static inline void spi_hid_device_descriptor_dump(struct device *dev,
		struct spi_hid_device_descriptor *desc)
{
	dev_info(dev, "device_descriptor:\n\
		\tbcdVersion         = 0x%04X\n\
		\tReportDescLength   = 0x%04X\n\
		\tReportDescRegister = 0x%04X\n\
		\tInputRegister      = 0x%04X\n\
		\tMaxInputLength     = 0x%04X\n\
		\tOutputRegister     = 0x%04X\n\
		\tMaxOutputLength    = 0x%04X\n\
		\tCommandRegister    = 0x%04X\n\
		\tVendorID           = 0x%04X\n\
		\tProductID          = 0x%04X\n\
		\tVersionID          = 0x%04X\n\
		\tDevicePowerSupport = 0x%02X\n\
		\tPowerResponseDelay = 0x%02X\n",
		desc->hid_version,
		desc->report_descriptor_length,
		desc->report_descriptor_register,
		desc->input_register,
		desc->max_input_length,
		desc->output_register,
		desc->max_output_length,
		desc->command_register,
		desc->vendor_id,
		desc->product_id,
		desc->version_id,
		desc->device_power_support,
		desc->power_response_delay
	);
}

#endif