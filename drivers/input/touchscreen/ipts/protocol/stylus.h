/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_PROTOCOL_STYLUS_H_
#define _IPTS_PROTOCOL_STYLUS_H_

#include <linux/build_bug.h>
#include <linux/types.h>

struct ipts_stylus_report {
	u8 reports;
	u8 reserved[3];
	u8 data[];
} __packed;

struct ipts_stylus_report_serial {
	u8 reports;
	u8 reserved[3];
	u32 serial;
	u8 data[];
} __packed;

struct ipts_stylus_report_data {
	u16 timestamp;
	u16 mode;
	u16 x;
	u16 y;
	u16 pressure;
	u16 altitude;
	u16 azimuth;
	u16 reserved;
} __packed;

struct ipts_stylus_report_data_no_tilt {
	u8 reserved[4];
	u8 mode;
	u16 x;
	u16 y;
	u16 pressure;
	u8 reserved2;
} __packed;

#define IPTS_STYLUS_REPORT_MODE_PROX   BIT(0)
#define IPTS_STYLUS_REPORT_MODE_TOUCH  BIT(1)
#define IPTS_STYLUS_REPORT_MODE_BUTTON BIT(2)
#define IPTS_STYLUS_REPORT_MODE_ERASER BIT(3)

static_assert(sizeof(struct ipts_stylus_report) == 4);
static_assert(sizeof(struct ipts_stylus_report_serial) == 8);
static_assert(sizeof(struct ipts_stylus_report_data) == 16);
static_assert(sizeof(struct ipts_stylus_report_data_no_tilt) == 12);

#endif /* _IPTS_PAYLOAD_STYLUS_H_ */
