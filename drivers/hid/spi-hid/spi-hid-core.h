/* SPDX-License-Identifier: GPL-2.0 */
/*
 * spi-hid-core.h
 *
 * Copyright (c) 2020 Microsoft Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#ifndef SPI_HID_CORE_H
#define SPI_HID_CORE_H

#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/pinctrl/consumer.h>
#include <linux/spi/spi.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/*
 * spi-hid-dev events which may occur on the event callback function.
 * The event callback function may be called in interupt thread context and
 * should not be blocked or run for a long time, it is adviced that all work
 * resulting from these events are executed on a separate work queue thread.
 * EVENT_NONE is a noop event, can be ignored
 * EVENT_ERROR indicates an error has occurred and the device should be reset.
 *   Client must ensure all fetched input reports are out of scope and reset
 *   the hardware which automatically reinitializes the device and bus.
 * EVENT_RESET indicates that the device has reset, either because an error has
 *   occurred, or as a result of a hard device reset (from init or error event).
 *   Client must ensure all fetched input reports are out of scope and indicate
 *   that it is ready to restart the driver by calling the _restart() function.
 * EVENT_READY indicates that the device is initialized and ready to generate
 *   input reports and receive output reports.
 * EVENT_INPUT_REPORT indicates that at least one unsolicited input report is
 *   available to be fetched by calling the _input_report() function.
 * EVENT_RESPONSE indicates that an output report response is available to be
 *   fetched by calling the _input_report() function. The response event is
 *   functionally equivialent to the input report event to the driver, but
 *   gives the client an opportunity to fetch unsolicited reports on a
 *   different thread to responses, with a higher priority if necessary to
 *   reduce potential input latency.
 * EVENT_WAKEUP indicates that an irq has arrived from a device in a sleep
 *   power state. The client is responsible for handling the irq and set device
 *   into an awake power state.
 */
#define SPI_HID_DEV_EVENT_NONE			0
#define SPI_HID_DEV_EVENT_ERROR			1
#define SPI_HID_DEV_EVENT_RESET			2
#define SPI_HID_DEV_EVENT_READY			3
#define SPI_HID_DEV_EVENT_INPUT_REPORT		4
#define SPI_HID_DEV_EVENT_RESPONSE		5
#define SPI_HID_DEV_EVENT_WAKEUP		6

#define SPI_HID_BUS_STOP			0
#define SPI_HID_BUS_ERROR_SPI_QUEUE		1
#define SPI_HID_BUS_ERROR_SPI_STATUS		2
#define SPI_HID_BUS_ERROR_SYNC_BYTE		3
#define SPI_HID_BUS_ERROR_VERSION		4
#define SPI_HID_BUS_ERROR_BUF_SIZE		5
#define SPI_HID_BUS_ERROR_RESET			6
#define SPI_HID_BUS_ERROR_STOP			7

/* Protocol constants */
#define SPI_HID_READ_APPROVAL_CONSTANT		0xff
#define SPI_HID_INPUT_HEADER_SYNC_BYTE		0x5a

#define SPI_HID_INPUT_HEADER_VERSION		0x02
#define SPI_HID_OUTPUT_HEADER_VERSION		0x02

#define SPI_HID_READ_APPROVAL_OPCODE_READ	0x0b
#define SPI_HID_OUTPUT_HEADER_OPCODE_WRITE	0x02

#define SPI_HID_DEFAULT_INPUT_REGISTER		0x1000
#define SPI_HID_SUPPORTED_VERSION		0x0100

/* Protocol message size constants */
#define SPI_HID_READ_APPROVAL_LEN		5
#define SPI_HID_INPUT_HEADER_LEN		4
#define SPI_HID_INPUT_BODY_LEN			3

#define SPI_HID_OUTPUT_HEADER_LEN		6
#define SPI_HID_OUTPUT_BODY_LEN			4

/* Protocol message type constants */
#define SPI_HID_REPORT_TYPE_DATA		0x01
#define SPI_HID_REPORT_TYPE_RESET_RESP		0x03
#define SPI_HID_REPORT_TYPE_COMMAND_RESP	0x04
#define SPI_HID_REPORT_TYPE_GET_FEATURE_RESP	0x05
#define SPI_HID_REPORT_TYPE_DEVICE_DESC		0x07
#define SPI_HID_REPORT_TYPE_REPORT_DESC		0x08

#define SPI_HID_CONTENT_TYPE_COMMAND		0x00
#define SPI_HID_CONTENT_TYPE_SET_FEATURE	0x03
#define SPI_HID_CONTENT_TYPE_GET_FEATURE	0x04
#define SPI_HID_CONTENT_TYPE_OUTPUT_REPORT	0x05

#define SPI_HID_COMMAND_SET_POWER		0x01

#define SPI_HID_POWER_SUPPORT_NONE		0x01
#define SPI_HID_POWER_SUPPORT_NO_RESP		0x02
#define SPI_HID_POWER_SUPPORT_RESP		0x03

#define SPI_HID_POWER_MODE_ACTIVE		0x01 /* "Active" - D0 */
#define SPI_HID_POWER_MODE_SLEEP		0x02 /* "Doze" - D2 */
#define SPI_HID_POWER_MODE_OFF			0x03
#define SPI_HID_POWER_MODE_WAKING_SLEEP		0x04 /* "Suspend" - D3/D3* */

#define SPI_HID_HEARTBEAT_REPORT_ID		0xFE

#define SPI_HID_INPUT_STAGE_IDLE	0
#define SPI_HID_INPUT_STAGE_BODY	1

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
	__le16 wFlags;
	__u8 reserved[4];
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

struct spi_hid_input_buf {
	__u8 header[SPI_HID_INPUT_HEADER_LEN];
	__u8 body[SPI_HID_INPUT_BODY_LEN];
	u8 content[SZ_8K];
};

struct spi_hid_output_buf {
	__u8 header[SPI_HID_OUTPUT_HEADER_LEN];
	__u8 body[SPI_HID_OUTPUT_BODY_LEN];
	u8 content[SZ_8K];
};

struct spi_hid_input_report {
	u8 report_type;
	u16 content_length;
	u8 content_id;
	u8 *content;
};

struct spi_hid_output_report {
	u8 content_type;
	u16 content_length;
	u8 content_id;
	u8 *content;
};

struct spi_hid_input_header {
	u8 version;
	u8 report_type;
	u8 fragment_id;
	u16 report_length;
	u8 sync_const;
};

struct spi_hid_input_body {
	u16 content_length;
	u8 content_id;
};

struct spi_hid {
	struct spi_device	*spi;
	struct hid_device	*hid;

	struct spi_transfer	input_transfer[2];
	struct spi_transfer	output_transfer;
	struct spi_message	input_message;
	struct spi_message	output_message;

	struct spi_hid_device_descriptor desc;
	struct spi_hid_output_buf output;
	struct spi_hid_input_buf input;
	struct spi_hid_input_buf response;

	spinlock_t		input_lock;

	u32 device_descriptor_register;
	u32 input_transfer_pending;
	u32 input_stage;

	u16 hid_desc_addr;
	u8 power_state;
	u8 attempts;

	/*
	* ready flag indicates that the FW is ready to accept commands and requests.
	* The FW becomes ready after sending the report descriptor.
	*/
	bool ready;
	/*
	* refresh_in_progress is set to true while the refresh_device worker thread
	* is destroying and recreating the hidraw device. When this flag is set to
	* true, the ll_close and ll_open functions will not cause power state changes
	*/
	bool refresh_in_progress;

	bool irq_enabled;

	struct regulator *supply;
	struct pinctrl *pinctrl;
	struct pinctrl_state *pinctrl_reset;
	struct pinctrl_state *pinctrl_active;
	struct pinctrl_state *pinctrl_sleep;
	struct work_struct reset_work;
	struct work_struct create_device_work;
	struct work_struct refresh_device_work;
	struct work_struct error_work;

	struct mutex lock;
	struct completion output_done;

	__u8 read_approval[SPI_HID_READ_APPROVAL_LEN];

	u32 report_descriptor_crc32;

	u32 regulator_error_count;
	int regulator_last_error;

	u32 bus_error_count;
	int bus_last_error;

	u32 logic_error_count;
	int logic_last_error;

	u32 dir_count;
	u32 powered;
};

#endif
