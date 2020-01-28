/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_PROTOCOL_TOUCH_H_
#define _IPTS_PROTOCOL_TOUCH_H_

#include <linux/types.h>

struct ipts_touch_data {
	u32 type;
	u32 size;
	u32 buffer;
	u8 reserved1[20];
	u8 transaction;
	u8 reserved2[31];
	u8 data[];
} __packed;

struct ipts_feedback {
	u32 type;
	u32 size;
	u32 transaction;
	u8 reserved[52];
	u8 data[];
} __packed;

struct ipts_stylus_report {
	u16 timestamp;
	u16 mode;
	u16 x;
	u16 y;
	u16 pressure;
	u16 altitude;
	u16 azimuth;
	u16 reserved;
} __packed;

struct ipts_stylus_report_gen1 {
	u8 mode;
	u16 x;
	u16 y;
	u16 pressure;
	u8 reserved[5];
} __packed;

struct ipts_singletouch_report {
	u8 touch;
	u16 x;
	u16 y;
} __packed;

#define IPTS_STYLUS_REPORT_MODE_PROXIMITY	BIT(0)
#define IPTS_STYLUS_REPORT_MODE_TOUCH		BIT(1)
#define IPTS_STYLUS_REPORT_MODE_BUTTON		BIT(2)
#define IPTS_STYLUS_REPORT_MODE_RUBBER		BIT(3)

static_assert(sizeof(struct ipts_touch_data) == 64);
static_assert(sizeof(struct ipts_feedback) == 64);
static_assert(sizeof(struct ipts_stylus_report) == 16);
static_assert(sizeof(struct ipts_stylus_report_gen1) == 12);
static_assert(sizeof(struct ipts_singletouch_report) == 5);

#endif /* _IPTS_PROTOCOL_TOUCH_H_ */
