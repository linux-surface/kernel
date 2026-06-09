/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Microsoft Corporation
 * Copyright (c) 2026 Google LLC
 */

#ifndef SPI_HID_CORE_H
#define SPI_HID_CORE_H

#include <linux/hid-over-spi.h>
#include <linux/spi/spi.h>

#include <drm/drm_panel.h>

/* Protocol message size constants */
#define SPI_HID_READ_APPROVAL_LEN		5
#define SPI_HID_OUTPUT_HEADER_LEN		8

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

/* Driver context */
struct spi_hid {
	struct spi_device	*spi;	/* spi device. */
	struct hid_device	*hid;	/* pointer to corresponding HID dev. */

	struct spi_transfer	input_transfer[2];	/* Transfer buffer for read and write. */
	struct spi_message	input_message;	/* used to execute a sequence of spi transfers. */

	struct spihid_ops	*ops;
	struct spi_hid_conf	*conf;

	struct spi_hid_device_descriptor desc;	/* HID device descriptor. */
	struct spi_hid_output_buf *output;	/* Output buffer. */
	struct spi_hid_input_buf *input;	/* Input buffer. */
	struct spi_hid_input_buf *response;	/* Response buffer. */

	struct drm_panel_follower panel_follower;
	bool	is_panel_follower;
	bool	panel_follower_work_finished;

	u16 response_length;
	u16 bufsize;

	enum hidspi_power_state power_state;

	u8 reset_attempts;	/* The number of reset attempts. */

	unsigned long flags;	/* device flags. */

	struct work_struct reset_work;
	struct work_struct panel_follower_work;

	/* Control lock to ensure complete output transaction. */
	struct mutex output_lock;
	/* Power lock to make sure one power state change at a time. */
	struct mutex power_lock;
	/* I/O lock to prevent concurrent output writes during the input read. */
	struct mutex io_lock;

	struct completion output_done;

	u8 read_approval_header[SPI_HID_READ_APPROVAL_LEN];
	u8 read_approval_body[SPI_HID_READ_APPROVAL_LEN];

	u32 report_descriptor_crc32;	/* HID report descriptor crc32 checksum. */

	u32 regulator_error_count;
	int regulator_last_error;
	u32 bus_error_count;
	int bus_last_error;
	u32 dir_count;		/* device initiated reset count. */
};

#endif /* SPI_HID_CORE_H */
