/*
 * spi-hid-protocol.h
 *
 * Copyright (c) 2020 Microsoft Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#ifndef SPI_HID_PROTOCOL_H
#define SPI_HID_PROTOCOL_H

#include <linux/types.h> // u8, u16, etc.

#include "spi-hid-device-descriptor.h"

/* Constants and definitions as described in the hid-over-spi specification v0.9
 * as well as utility structs, definitions and functions for representing and
 * converting between bus and cpu native c struct representations.
 */

// Protocol constants
#define SPI_HID_READ_APPROVAL_CONSTANT 0xFF
#define SPI_HID_INPUT_HEADER_SYNC_BYTE 0x5A
/* MSCHANGE START: note header version 2 is reported by d5 chip but not
* consistent with HID over SPI v0.9 spec from MS (claims it must be version 1),
* discuss with d5 fw team or todo: implement quirk for handling */
#define SPI_HID_INPUT_HEADER_VERSION  0x02
#define SPI_HID_OUTPUT_HEADER_VERSION 0x02
/* MSCHANGE END */
#define SPI_HID_READ_APPROVAL_OPCODE_READ 0x0B
#define SPI_HID_OUTPUT_HEADER_OPCODE_WRITE 0x02

#define SPI_HID_DEFAULT_INPUT_REGISTER 0x1000
#define SPI_HID_SUPPORTED_VERSION 0x0100

// Protocol message size constants
#define SPI_HID_READ_APPROVAL_LEN 5
#define SPI_HID_INPUT_HEADER_LEN  4
#define SPI_HID_INPUT_BODY_LEN    3

#define SPI_HID_OUTPUT_HEADER_LEN 6
#define SPI_HID_OUTPUT_BODY_LEN   4

// Protocol message type constants
#define SPI_HID_REPORT_TYPE_DATA             0x01
#define SPI_HID_REPORT_TYPE_RESET_RESP       0x03
#define SPI_HID_REPORT_TYPE_COMMAND_RESP     0x04
#define SPI_HID_REPORT_TYPE_GET_FEATURE_RESP 0x05
#define SPI_HID_REPORT_TYPE_DEVICE_DESC      0x07
#define SPI_HID_REPORT_TYPE_REPORT_DESC      0x08

#define SPI_HID_CONTENT_TYPE_COMMAND       0x00
#define SPI_HID_CONTENT_TYPE_SET_FEATURE   0x03
#define SPI_HID_CONTENT_TYPE_GET_FEATURE   0x04
#define SPI_HID_CONTENT_TYPE_OUTPUT_REPORT 0x05

#define SPI_HID_COMMAND_SET_POWER 0x01

#define SPI_HID_POWER_SUPPORT_NONE    0b00
#define SPI_HID_POWER_SUPPORT_NO_RESP 0b10
#define SPI_HID_POWER_SUPPORT_RESP    0b11
// 0b01 reserved

#define SPI_HID_POWER_MODE_ACTIVE       0x01 /* "Active" - D0 */
#define SPI_HID_POWER_MODE_SLEEP        0x02 /* "Doze" - D2 */
#define SPI_HID_POWER_MODE_OFF          0x03
/* MSCHANGE START, non-spec power mode */
#define SPI_HID_POWER_MODE_WAKING_SLEEP 0x04 /* "Suspend" - D3/D3* */
/* MSCHANGE END */

// Protocol message buffer definitions
typedef u8 spi_hid_read_approval_buf[SPI_HID_READ_APPROVAL_LEN];
typedef u8 spi_hid_input_header_buf[SPI_HID_INPUT_HEADER_LEN];
typedef u8 spi_hid_input_body_buf[SPI_HID_INPUT_BODY_LEN];

typedef u8 spi_hid_output_header_buf[SPI_HID_OUTPUT_HEADER_LEN];
typedef u8 spi_hid_output_body_buf[SPI_HID_OUTPUT_BODY_LEN];

struct spi_hid_input_transaction_buf {
  spi_hid_read_approval_buf read_approval;
  u8 content[];
};

struct spi_hid_input_buf {
	struct {
		spi_hid_read_approval_buf read_approval;
		spi_hid_input_header_buf header;
	} header;
	struct {
		spi_hid_read_approval_buf read_approval;
		spi_hid_input_body_buf body;
	} body;
	u8 content[];
};

typedef u8 spi_hid_input_init_buf[sizeof(struct spi_hid_input_buf) +
		sizeof(struct spi_hid_device_desc_raw)];

struct spi_hid_output_buf {
	spi_hid_output_header_buf header;
	spi_hid_output_body_buf body;
	u8 content[];
};

struct spi_hid_content {
	u16 length;
	u8 id;
	u8 data[];
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

static inline void spi_hid_input_header(spi_hid_input_header_buf buf,
		struct spi_hid_input_header *header)
{
	header->version       = (buf[0] >> 0) & 0xf;
	header->report_type   = (buf[0] >> 4) & 0xf;
	header->fragment_id   = (buf[1] >> 0) & 0xf;
	header->report_length = ((((buf[1] >> 4) & 0xf) << 0) |
	                           (buf[2] << 4)) * 4;
	header->sync_const    = buf[3];
}

static inline void spi_hid_input_body(spi_hid_input_body_buf buf,
		struct spi_hid_input_body *body)
{
	body->content_length = (buf[0] | (buf[1] << 8)) -
			(sizeof(body->content_length) + sizeof(body->content_id));
	body->content_id = buf[2];
}

static inline void spi_hid_input_report_prepare(struct spi_hid_input_buf *buf,
		struct spi_hid_input_report *report)
{
	struct spi_hid_input_header header;
	struct spi_hid_input_body body;
	spi_hid_input_header(buf->header.header, &header);
	spi_hid_input_body(buf->body.body, &body);
	report->report_type = header.report_type;
	report->content_length = body.content_length;
	report->content_id = body.content_id;
	report->content = buf->content;
}

static inline void spi_hid_output_header(spi_hid_output_header_buf buf,
		u16 output_register, u16 output_report_length)
{
	// Not yet implemented: opcodes for multi line spi
	buf[0] = SPI_HID_OUTPUT_HEADER_OPCODE_WRITE;
	buf[1] = (output_register >> 16) & 0xff;
	buf[2] = (output_register >> 8) & 0xff;
	buf[3] = (output_register >> 0) & 0xff;
	buf[4] = (SPI_HID_OUTPUT_HEADER_VERSION << 0) |
			(((output_report_length >> 0) & 0xf) << 4);
	buf[5] = (output_report_length >> 4) & 0xff;
}

static inline void spi_hid_output_body(spi_hid_output_body_buf buf,
		struct spi_hid_output_report *report)
{
	// According to spec the content_length field includes the length of the
	// content length (2) and content (1) id as well.
	u16 content_length = report->content_length +
			sizeof(report->content_length) + sizeof(report->content_id);
	buf[0] = report->content_type;
	buf[1] = (content_length >> 0) & 0xff;
	buf[2] = (content_length >> 8) & 0xff;
	buf[3] = report->content_id;
}

static inline void spi_hid_read_approval(u32 input_register, u8 *buf)
{
	// Not yet implemented: opcodes for multi line spi
	buf[0] = SPI_HID_READ_APPROVAL_OPCODE_READ;
	buf[1] = (input_register >> 16) & 0xff;
	buf[2] = (input_register >> 8) & 0xff;
	buf[3] = (input_register >> 0) & 0xff;
	buf[4] = SPI_HID_READ_APPROVAL_CONSTANT;
}

#endif /* SPI_HID_PROTOCOL_H */